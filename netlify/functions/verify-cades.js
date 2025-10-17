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
    const body = JSON.parse(event.body);
    const { fileData, fileName } = body;
    
    if (!fileData) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'No file data provided', valid: false })
      };
    }

    if (!/^[A-Za-z0-9+/=]+$/.test(fileData)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid Base64 data format', valid: false })
      };
    }

    const estimatedSize = (fileData.length * 3) / 4;
    if (estimatedSize > 6 * 1024 * 1024) {
      return {
        statusCode: 413,
        headers,
        body: JSON.stringify({ 
          error: 'File too large',
          message: 'File must be under 6MB',
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
    console.error('Handler error:', error);
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
        error: 'Invalid CAdES/PKCS#7 structure'
      };
    }

    if (!p7.rawCapture || !p7.rawCapture.signature) {
      return {
        valid: false,
        format: 'CAdES',
        fileName: fileName,
        error: 'Not a valid signed data structure'
      };
    }

    if (!p7.certificates || p7.certificates.length === 0) {
      return {
        valid: false,
        format: 'CAdES',
        fileName: fileName,
        error: 'No certificates found'
      };
    }

    const signerCert = p7.certificates[0];
    const signerInfo = extractCertificateInfo(signerCert);

    const isDetached = !p7.content || p7.content.length === 0;

    let signatureValid = false;
    let verificationError = null;

    try {
      const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
      const attrs = p7.rawCapture.authenticatedAttributes;
      
      if (attrs) {
        const set = forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.SET,
          true,
          attrs
        );
        
        const attrDer = forge.asn1.toDer(set);
        const md = forge.md[hashAlgorithm].create();
        md.update(attrDer.data);
        
        const signature = p7.rawCapture.signature;
        const publicKey = signerCert.publicKey;
        signatureValid = publicKey.verify(md.digest().bytes(), signature);
        
        if (!isDetached && p7.rawCapture.content) {
          let contentDigestValid = false;
          const contentMd = forge.md[hashAlgorithm].create();
          contentMd.update(p7.rawCapture.content);
          const contentDigest = contentMd.digest().bytes();
          
          for (let attr of attrs) {
            try {
              const attrOid = forge.asn1.derToOid(attr.value[0].value);
              if (attrOid === forge.pki.oids.messageDigest) {
                const attrDigest = attr.value[1].value[0].value;
                contentDigestValid = (attrDigest === contentDigest);
                break;
              }
            } catch (e) {
              continue;
            }
          }
          
          signatureValid = signatureValid && contentDigestValid;
          
          if (!contentDigestValid) {
            verificationError = 'Content digest mismatch';
          }
        }
        
      } else {
        if (!isDetached && p7.rawCapture.content) {
          const md = forge.md[hashAlgorithm].create();
          md.update(p7.rawCapture.content);
          
          const signature = p7.rawCapture.signature;
          signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
        } else {
          verificationError = 'Detached signature requires original content';
          signatureValid = false;
        }
      }
      
    } catch (e) {
      verificationError = e.message;
      signatureValid = false;
    }

    const now = new Date();
    const certValid = now >= signerCert.validity.notBefore && 
                     now <= signerCert.validity.notAfter;

    const isSelfSigned = signerCert.issuer.hash === signerCert.subject.hash;

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
            continue;
          }
        }
      }
    } catch (e) {
      // Ignore
    }

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
      result.warnings.push('Detached signature - original content not included');
      if (!signatureValid) {
        result.warnings.push('Cannot verify without original content');
      }
    }

    if (isSelfSigned) {
      result.warnings.push('Certificate is self-signed');
    }
    
    if (!certValid) {
      result.warnings.push('Certificate is expired or not yet valid');
    }

    if (verificationError) {
      result.warnings.push('Verification issue: ' + verificationError);
    }

    result.warnings.push('CRL/OCSP not checked');

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
    
    const oidStr = forge.asn1.derToOid(oidBuffer);
    
    if (oidStr === forge.pki.oids.sha1 || oidStr.includes('1.3.14.3.2.26')) {
      return 'sha1';
    } else if (oidStr === forge.pki.oids.sha256 || oidStr.includes('2.16.840.1.101.3.4.2.1')) {
      return 'sha256';
    } else if (oidStr === forge.pki.oids.sha384 || oidStr.includes('2.16.840.1.101.3.4.2.2')) {
      return 'sha384';
    } else if (oidStr === forge.pki.oids.sha512 || oidStr.includes('2.16.840.1.101.3.4.2.3')) {
      return 'sha512';
    }
    
    return 'sha256';
  } catch (e) {
    return 'sha256';
  }
}

function getSignatureAlgorithm(p7) {
  const hashAlg = getHashAlgorithmFromDigestOid(p7);
  const hashName = hashAlg.toUpperCase();
  return `RSA-${hashName}`;
}
