const forge = require('node-forge');

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { fileData, fileName } = JSON.parse(event.body);
    
    if (!fileData) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'No file data provided' })
      };
    }

    const buffer = Buffer.from(fileData, 'base64');
    const result = await verifyCAdESSignature(buffer, fileName);
    
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

async function verifyCAdESSignature(dataBuffer, fileName) {
  try {
    // Parse PKCS#7/CMS structure
    let p7;
    try {
      const der = forge.util.createBuffer(dataBuffer.toString('binary'));
      const asn1 = forge.asn1.fromDer(der);
      p7 = forge.pkcs7.messageFromAsn1(asn1);
    } catch (e) {
      return {
        valid: false,
        format: 'CAdES',
        fileName: fileName,
        error: 'Invalid CAdES/PKCS#7 structure: ' + e.message
      };
    }

    // Check if this is a signed data message
    if (!p7.rawCapture || !p7.rawCapture.content) {
      return {
        valid: false,
        format: 'CAdES',
        fileName: fileName,
        error: 'Not a valid signed data structure'
      };
    }

    // Extract certificate information
    if (!p7.certificates || p7.certificates.length === 0) {
      return {
        valid: false,
        format: 'CAdES',
        fileName: fileName,
        error: 'No certificates found in signature'
      };
    }

    const signerCert = p7.certificates[0];
    const signerInfo = extractCertificateInfo(signerCert);

    // Verify signature
    let signatureValid = false;
    let verificationError = null;

    try {
      // Get the signed content
      const content = p7.rawCapture.content;
      
      // Create message digest
      const md = forge.md.sha256.create();
      md.update(content);
      
      // Get signature
      const signature = p7.rawCapture.signature;
      
      // Verify with public key
      const publicKey = signerCert.publicKey;
      signatureValid = publicKey.verify(md.digest().bytes(), signature);
      
    } catch (e) {
      verificationError = e.message;
      // Try alternative verification
      try {
        signatureValid = p7.verify();
      } catch (e2) {
        verificationError = e2.message;
      }
    }

    // Check certificate validity
    const now = new Date();
    const certValid = now >= signerCert.validity.notBefore && 
                     now <= signerCert.validity.notAfter;

    const isSelfSigned = signerCert.issuer.hash === signerCert.subject.hash;

    // Extract signing time
    let signatureDate = 'Unknown';
    try {
      if (p7.rawCapture.authenticatedAttributes) {
        for (let attr of p7.rawCapture.authenticatedAttributes) {
          if (attr.type === forge.pki.oids.signingTime) {
            signatureDate = new Date(attr.value).toLocaleString();
            break;
          }
        }
      }
    } catch (e) {
      // Signing time not available
    }

    // Determine signature algorithm
    const signatureAlgorithm = getSignatureAlgorithm(p7);

    // Check for attached or detached signature
    const isDetached = !p7.content || p7.content.length === 0;

    const result = {
      valid: signatureValid && certValid,
      format: 'CAdES (CMS Advanced Electronic Signature)',
      fileName: fileName,
      cryptographicVerification: true,
      signatureValid: signatureValid,
      certificateValid: certValid,
      signatureType: isDetached ? 'Detached' : 'Attached',
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

    if (isDetached) {
      result.warnings.push('This is a detached signature - original content not included in signature file');
    }

    if (isSelfSigned) {
      result.warnings.push('Certificate is self-signed and not issued by a trusted Certificate Authority');
    }
    
    if (!certValid) {
      result.warnings.push('Certificate is expired or not yet valid');
    }

    if (verificationError) {
      result.warnings.push('Signature verification note: ' + verificationError);
    }

    result.warnings.push('Certificate revocation status (CRL/OCSP) not checked - requires external validation');

    return result;

  } catch (error) {
    return {
      valid: false,
      format: 'CAdES',
      fileName: fileName,
      error: 'Verification failed: ' + error.message
    };
  }
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
    if (oid && oid.includes) {
      if (oid.includes('sha256')) return 'RSA-SHA256';
      if (oid.includes('sha384')) return 'RSA-SHA384';
      if (oid.includes('sha512')) return 'RSA-SHA512';
      if (oid.includes('sha1')) return 'RSA-SHA1';
    }
    return 'RSA-SHA256';
  } catch (e) {
    return 'RSA-SHA256';
  }
}
