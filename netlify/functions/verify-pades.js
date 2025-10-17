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
    const result = await verifyPAdESSignature(buffer, fileName);
    
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

function getASN1Length(bytes, offset) {
  // Read ASN.1 length field
  const firstByte = bytes.charCodeAt(offset);
  
  if ((firstByte & 0x80) === 0) {
    // Short form: length is in the first byte
    return { length: firstByte, headerLength: 1 };
  } else {
    // Long form: first byte tells us how many following bytes contain the length
    const numLengthBytes = firstByte & 0x7F;
    let length = 0;
    
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | bytes.charCodeAt(offset + 1 + i);
    }
    
    return { length: length, headerLength: 1 + numLengthBytes };
  }
}

function extractPKCS7Only(signatureBytes) {
  // Parse the top-level SEQUENCE to get exact length
  // ASN.1 structure: TAG (1 byte) + LENGTH (1+ bytes) + VALUE
  
  if (signatureBytes.length < 2) {
    throw new Error('Signature too short');
  }
  
  const tag = signatureBytes.charCodeAt(0);
  
  // Should be SEQUENCE (0x30)
  if (tag !== 0x30) {
    throw new Error('Invalid ASN.1 tag, expected SEQUENCE');
  }
  
  const lengthInfo = getASN1Length(signatureBytes, 1);
  const totalLength = 1 + lengthInfo.headerLength + lengthInfo.length;
  
  // Return only the PKCS#7 portion (no trailing data)
  return signatureBytes.substring(0, totalLength);
}

async function verifyPAdESSignature(pdfBuffer, fileName) {
  try {
    const pdfString = pdfBuffer.toString('latin1');
    
    // Check if it's a valid PDF
    if (!pdfString.startsWith('%PDF-')) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Not a valid PDF file'
      };
    }

    // Find ByteRange
    const byteRangeMatch = pdfString.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
    if (!byteRangeMatch) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'No valid PAdES signature found (no ByteRange)'
      };
    }

    const byteRange = [
      parseInt(byteRangeMatch[1]),
      parseInt(byteRangeMatch[2]),
      parseInt(byteRangeMatch[3]),
      parseInt(byteRangeMatch[4])
    ];

    // Validate ByteRange values
    if (byteRange[0] < 0 || byteRange[1] <= 0 || byteRange[2] <= 0 || byteRange[3] <= 0) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Invalid ByteRange values'
      };
    }

    // Extract signature hex
    const signatureHex = extractSignatureHex(pdfString, byteRange);
    if (!signatureHex) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Could not extract signature from Contents'
      };
    }

    // Convert hex to bytes
    let signatureBytes;
    try {
      signatureBytes = hexToBytes(signatureHex);
    } catch (e) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Invalid signature hex encoding'
      };
    }

    // Extract only the PKCS#7 structure (remove trailing data)
    let pkcs7Bytes;
    try {
      pkcs7Bytes = extractPKCS7Only(signatureBytes);
    } catch (e) {
      console.error('PKCS#7 extraction error:', e);
      pkcs7Bytes = signatureBytes; // Try with full data if extraction fails
    }

    // Parse PKCS#7
    let p7;
    try {
      const der = forge.util.createBuffer(pkcs7Bytes, 'raw');
      const asn1 = forge.asn1.fromDer(der);
      p7 = forge.pkcs7.messageFromAsn1(asn1);
    } catch (e) {
      console.error('PKCS#7 parsing error:', e);
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Invalid PKCS#7 structure: ' + e.message
      };
    }

    // Verify it's a signed data structure
    if (!p7.rawCapture || !p7.rawCapture.signature) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'Not a valid signed data structure'
      };
    }

    if (!p7.certificates || p7.certificates.length === 0) {
      return {
        valid: false,
        format: 'PAdES',
        fileName: fileName,
        error: 'No certificates found in signature'
      };
    }

    const signerCert = p7.certificates[0];
    const signerInfo = extractCertificateInfo(signerCert);

    // Get the signed data (ByteRange portions)
    const signedData = Buffer.concat([
      pdfBuffer.slice(byteRange[0], byteRange[0] + byteRange[1]),
      pdfBuffer.slice(byteRange[2], byteRange[2] + byteRange[3])
    ]);

    let signatureValid = false;
    let verificationError = null;
    
    try {
      const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
      const attrs = p7.rawCapture.authenticatedAttributes;
      
      if (attrs) {
        // Verify signature on authenticated attributes
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
        
        // Verify message digest in authenticated attributes matches content
        let contentDigestValid = false;
        const contentMd = forge.md[hashAlgorithm].create();
        contentMd.update(signedData.toString('binary'));
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
          verificationError = 'Content digest mismatch - document may have been modified';
        }
        
      } else {
        // No authenticated attributes - verify signature directly on content
        const md = forge.md[hashAlgorithm].create();
        md.update(signedData.toString('binary'));
        
        const signature = p7.rawCapture.signature;
        signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
      }
      
    } catch (e) {
      console.error('Signature verification error:', e);
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
      const attrs = p7.rawCapture.authenticatedAttributes;
      if (attrs) {
        for (let attr of attrs) {
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

    if (isSelfSigned) {
      result.warnings.push('Certificate is self-signed');
    }
    
    if (!certValid) {
      result.warnings.push('Certificate is expired or not yet valid');
    }

    if (verificationError) {
      result.warnings.push('Verification issue: ' + verificationError);
    }

    result.warnings.push('CRL/OCSP revocation status not checked');

    return result;

  } catch (error) {
    console.error('Verification error:', error);
    return {
      valid: false,
      format: 'PAdES',
      fileName: fileName,
      error: 'Verification failed: ' + error.message
    };
  }
}

function extractSignatureHex(pdfString, byteRange) {
  try {
    // Find the Contents field which contains the signature
    const contentsMatch = pdfString.match(/\/Contents\s*<([0-9A-Fa-f]+)>/);
    if (contentsMatch) {
      return contentsMatch[1];
    }

    // Alternative: extract from ByteRange positions
    const start = byteRange[0] + byteRange[1];
    const end = byteRange[2];
    
    if (start >= end || end > pdfString.length) {
      return null;
    }
    
    // Look for hex content between < and >
    const section = pdfString.substring(start, end);
    const hexMatch = section.match(/<([0-9A-Fa-f]+)>/);
    
    if (hexMatch) {
      return hexMatch[1];
    }
    
    return null;
  } catch (e) {
    console.error('Signature extraction error:', e);
    return null;
  }
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  
  if (!/^[0-9A-Fa-f]+$/.test(hex)) {
    throw new Error('Invalid hex characters');
  }
  
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
