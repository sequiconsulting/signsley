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

    // Validate Base64 format
    if (!/^[A-Za-z0-9+/=]+$/.test(fileData)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          error: 'Invalid Base64 data format',
          valid: false 
        })
      };
    }

    // Validate file size (6MB Netlify limit)
    const estimatedSize = (fileData.length * 3) / 4;
    if (estimatedSize > 6 * 1024 * 1024) {
      return {
        statusCode: 413,
        headers,
        body: JSON.stringify({ 
          error: 'File too large',
          message: 'File must be under 6MB due to Netlify Functions limit',
          valid: false
        })
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

    // Verify the signature - CORRECTED METHOD
    let signatureValid = false;
    let verificationError = null;
    
    try {
      // Detect hash algorithm from signature
      const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
      
      // For PKCS#7, we must verify the authenticatedAttributes, not the content directly
      const attrs = p7.rawCapture.authenticatedAttributes;
      
      if (attrs) {
        // Create SET structure for authenticatedAttributes (required for PKCS#7)
        const set = forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.SET,
          true,
          attrs
        );
        
        // Convert to DER
        const attrDer = forge.asn1.toDer(set);
        
        // Hash the authenticatedAttributes
        const md = forge.md[hashAlgorithm].create();
        md.update(attrDer.data);
        
        // Verify signature with public key
        const signature = p7.rawCapture.signature;
        const publicKey = signerCert.publicKey;
        signatureValid = publicKey.verify(md.digest().bytes(), signature);
        
        // Also verify that messageDigest attribute matches the actual content hash
        let contentDigestValid = false;
        const contentMd = forge.md[hashAlgorithm].create();
        contentMd.update(signedData.toString('binary'));
        const contentDigest = contentMd.digest().bytes();
        
        // Find messageDigest in authenticatedAttributes
        for (let attr of attrs) {
          try {
            const attrOid = forge.asn1.derToOid(attr.value[0].value);
            if (attrOid === forge.pki.oids.messageDigest) {
              const attrDigest = attr.value[1].value[0].value;
              contentDigestValid = (attrDigest === contentDigest);
              break;
            }
          } catch (e) {
            // Continue checking other attributes
          }
        }
        
        // Signature is only valid if both signature and content digest are valid
        signatureValid = signatureValid && contentDigestValid;
        
        if (!contentDigestValid) {
          verificationError = 'Content digest does not match messageDigest attribute';
        }
        
      } else {
        // Fallback: signatures without authenticatedAttributes (rare, but possible)
        const md = forge.md[hashAlgorithm].create();
        md.update(signedData.toString('binary'));
        
        const signature = p7.rawCapture.signature;
        signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
      }
      
    } catch (e) {
      verificationError = e.message;
      signatureValid = false;
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
          try {
            const attrOid = forge.asn1.derToOid(attr.value[0].value);
            if (attrOid === forge.pki.oids.signingTime) {
              // Signing time is in the second value
              const timeValue = attr.value[1].value[0].value;
              signatureDate = new Date(timeValue).toLocaleString();
              break;
            }
          } catch (e) {
            // Continue checking other attributes
          }
        }
      }
    } catch (e) {
      // Signing time not available
    }

    // Get signature algorithm
    const signatureAlgorithm = getSignatureAlgorithm(p7);

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
      signatureAlgorithm: signatureAlgorithm,
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
      result.warnings.push('Signature verification issue: ' + verificationError);
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
  
  const hex = pdfString.substring(start, end);
  
  // Validate hex format (should only contain 0-9, A-F, a-f)
  if (!/^[0-9A-Fa-f]+$/.test(hex)) {
    console.error('Invalid hex signature format');
    return null;
  }
  
  // Validate length (should be even)
  if (hex.length % 2 !== 0) {
    console.error('Signature hex has odd length');
    return null;
  }
  
  return hex;
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

function getHashAlgorithmFromDigestOid(p7) {
  try {
    const oidBuffer = p7.rawCapture.digestAlgorithm;
    if (!oidBuffer) return 'sha256';
    
    // Convert to OID string
    const oidStr = forge.asn1.derToOid(oidBuffer);
    
    // Map OID to hash algorithm
    if (oidStr === forge.pki.oids.sha1 || oidStr.includes('1.3.14.3.2.26')) {
      return 'sha1';
    } else if (oidStr === forge.pki.oids.sha256 || oidStr.includes('2.16.840.1.101.3.4.2.1')) {
      return 'sha256';
    } else if (oidStr === forge.pki.oids.sha384 || oidStr.includes('2.16.840.1.101.3.4.2.2')) {
      return 'sha384';
    } else if (oidStr === forge.pki.oids.sha512 || oidStr.includes('2.16.840.1.101.3.4.2.3')) {
      return 'sha512';
    }
    
    return 'sha256'; // default
  } catch (e) {
    console.error('Error detecting hash algorithm:', e);
    return 'sha256'; // default fallback
  }
}

function getSignatureAlgorithm(p7) {
  const hashAlg = getHashAlgorithmFromDigestOid(p7);
  
  // Format as RSA-[HASH]
  const hashName = hashAlg.toUpperCase();
  return `RSA-${hashName}`;
}
