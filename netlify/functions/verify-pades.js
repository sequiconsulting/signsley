const forge = require('node-forge');
const pdfParse = require('pdf-parse');

exports.handler = async (event, context) => {
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight request
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    // Parse the incoming file data
    const { fileData, fileName } = JSON.parse(event.body);
    
    if (!fileData) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'No file data provided' })
      };
    }

    // Convert base64 to buffer
    const buffer = Buffer.from(fileData, 'base64');
    
    // Verify PAdES signature
    const result = await verifyPAdESSignature(buffer, fileName);
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(result)
    };

  } catch (error) {
    console.error('Verification error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Verification failed',
        message: error.message,
        valid: false
      })
    };
  }
};

async function verifyPAdESSignature(pdfBuffer, fileName) {
  try {
    const pdfString = pdfBuffer.toString('binary');
    
    // Extract ByteRange and signature
    const byteRangeMatch = pdfString.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
    if (!byteRangeMatch) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'No valid PAdES signature found - ByteRange missing'
      };
    }

    const byteRange = [
      parseInt(byteRangeMatch[1]),
      parseInt(byteRangeMatch[2]),
      parseInt(byteRangeMatch[3]),
      parseInt(byteRangeMatch[4])
    ];

    // Extract signature content
    const signatureHex = extractSignatureHex(pdfString, byteRange);
    if (!signatureHex) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Could not extract signature from PDF'
      };
    }

    // Convert hex signature to DER
    const signatureBytes = hexToBytes(signatureHex);
    
    // Parse PKCS#7 signature
    let p7;
    try {
      const asn1 = forge.asn1.fromDer(forge.util.createBuffer(signatureBytes));
      p7 = forge.pkcs7.messageFromAsn1(asn1);
    } catch (e) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Invalid PKCS#7 signature structure: ' + e.message
      };
    }

    // Extract certificate information
    const signerCert = p7.certificates[0];
    const signerInfo = extractCertificateInfo(signerCert);

    // Get the signed data (PDF content excluding signature)
    const signedData = Buffer.concat([
      pdfBuffer.slice(byteRange[0], byteRange[0] + byteRange[1]),
      pdfBuffer.slice(byteRange[2], byteRange[2] + byteRange[3])
    ]);

    // Verify the signature
    let signatureValid = false;
    let verificationError = null;
    
    try {
      // Create message digest
      const md = forge.md.sha256.create();
      md.update(signedData.toString('binary'));
      
      // Get the signature from PKCS#7
      const signature = p7.rawCapture.signature;
      
      // Verify signature with public key
      const publicKey = signerCert.publicKey;
      signatureValid = publicKey.verify(md.digest().bytes(), signature);
      
    } catch (e) {
      verificationError = e.message;
    }

    // Check certificate validity
    const now = new Date();
    const certValid = now >= signerCert.validity.notBefore && 
                     now <= signerCert.validity.notAfter;

    // Check if certificate is self-signed
    const isSelfSigned = signerCert.issuer.hash === signerCert.subject.hash;

    // Extract signature timestamp if present
    let signatureDate = 'Unknown';
    try {
      const attrs = p7.rawCapture.authenticatedAttributes;
      if (attrs) {
        // Look for signing time attribute
        for (let attr of attrs) {
          if (attr.type === forge.pki.oids.signingTime) {
            signatureDate = new Date(attr.value).toLocaleString();
            break;
          }
        }
      }
    } catch (e) {
      // Signing time not available
    }

    // Build result
    const result = {
      valid: signatureValid && certValid,
      format: 'PAdES (PDF Advanced Electronic Signature)',
      fileName: fileName,
      cryptographicVerification: true,
      signatureValid: signatureValid,
      certificateValid: certValid,
      signedBy: signerInfo.commonName,
      organization: signerInfo.organization,
      email: signerInfo.email,
      signatureDate: signatureDate,
      signatureAlgorithm: getSignatureAlgorithm(p7),
      certificateIssuer: signerInfo.issuer,
      certificateValidFrom: signerCert.validity.notBefore.toLocaleDateString(),
      certificateValidTo: signerCert.validity.notAfter.toLocaleDateString(),
      serialNumber: signerCert.serialNumber,
      isSelfSigned: isSelfSigned,
      warnings: []
    };

    // Add warnings
    if (isSelfSigned) {
      result.warnings.push('Certificate is self-signed and not issued by a trusted Certificate Authority');
    }
    
    if (!certValid) {
      result.warnings.push('Certificate is expired or not yet valid');
    }

    if (verificationError) {
      result.warnings.push('Signature verification error: ' + verificationError);
    }

    // Note about revocation
    result.warnings.push('Certificate revocation status (CRL/OCSP) not checked - requires external validation');

    return result;

  } catch (error) {
    return {
      valid: false,
      format: 'PAdES',
      fileName: fileName,
      error: 'Verification failed: ' + error.message
    };
  }
}

function extractSignatureHex(pdfString, byteRange) {
  const start = byteRange[0] + byteRange[1] + 1; // +1 to skip '<'
  const end = byteRange[2] - 1; // -1 to skip '>'
  
  if (start >= end || end > pdfString.length) {
    return null;
  }
  
  return pdfString.substring(start, end);
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return String.fromCharCode.apply(null, bytes);
}

function extractCertificateInfo(cert) {
  const subject = cert.subject.attributes;
  const issuer = cert.issuer.attributes;
  
  const info = {
    commonName: 'Unknown',
    organization: 'Unknown',
    email: 'Unknown',
    issuer: 'Unknown'
  };

  subject.forEach(attr => {
    if (attr.shortName === 'CN') info.commonName = attr.value;
    if (attr.shortName === 'O') info.organization = attr.value;
    if (attr.shortName === 'emailAddress') info.email = attr.value;
  });

  issuer.forEach(attr => {
    if (attr.shortName === 'CN') info.issuer = attr.value;
  });

  return info;
}

function getSignatureAlgorithm(p7) {
  try {
    const oid = p7.rawCapture.digestAlgorithm;
    if (oid.includes('sha256')) return 'RSA-SHA256';
    if (oid.includes('sha384')) return 'RSA-SHA384';
    if (oid.includes('sha512')) return 'RSA-SHA512';
    if (oid.includes('sha1')) return 'RSA-SHA1';
    return 'RSA-SHA256 (default)';
  } catch (e) {
    return 'RSA-SHA256';
  }
}
