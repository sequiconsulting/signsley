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
    if (!p7.rawCapture || !p7.rawCapture.signature) {
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

    // Check for attached or detached signature
    const isDetached = !p7.content || p7.content.length === 0;

    // Verify signature - CORRECTED METHOD
    let signatureValid = false;
    let verificationError = null;

    try {
      // Detect hash algorithm
      const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
      
      // For PKCS#7, we must verify the authenticatedAttributes if present
      const attrs = p7.rawCapture.authenticatedAttributes;
      
      if (attrs) {
        // Create SET structure for authenticatedAttributes
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
        
        // For attached signatures, also verify messageDigest attribute
        if (!isDetached && p7.rawCapture.content) {
          let contentDigestValid = false;
          const contentMd = forge.md[hashAlgorithm].create();
          contentMd.update(p7.rawCapture.content);
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
          
          signatureValid = signatureValid && contentDigestValid;
          
          if (!contentDigestValid) {
            verificationError = 'Content digest does not match messageDigest attribute';
          }
        }
        
      } else {
        // Fallback: signatures without authenticatedAttributes
        if (!isDetached && p7.rawCapture.content) {
          const md = forge.md[hashAlgorithm].create();
          md.update(p7.rawCapture.content);
          
          const signature = p7.rawCapture.signature;
          signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
        } else {
          verificationError = 'Detached signature cannot be verified without original content';
          signatureValid = false;
        }
      }
      
    } catch (e) {
      verificationError = e.message;
      signatureValid = false;
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
          try {
            const attrOid = forge.asn1.derToOid(attr.value[0].value);
            if (attrOid === forge.pki.oids.signingTime) {
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

    // Determine signature algorithm
    const signatureAlgorithm = getSignatureAlgorithm(p7);

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
      if (!signatureValid) {
        result.warnings.push('Detached signature cannot be fully verified without the original signed content');
      }
    }

    if (isSelfSigned) {
      result.warnings.push('Certificate is self-signed and not issued by a trusted Certificate Authority');
    }
    
    if (!certValid) {
      result.warnings.push('Certificate is expired or not yet valid');
    }

    if (verificationError) {
      result.warnings.push('Signature verification issue: ' + verificationError);
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
