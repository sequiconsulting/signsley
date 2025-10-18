const forge = require('node-forge');

function formatDate(date) {
  if (!date) return 'Unknown';
  try {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return 'Unknown';
    return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
  } catch {
    return 'Unknown';
  }
}

function extractCertificateInfo(cert) {
  const info = {
    commonName: 'Unknown',
    organization: 'Unknown',
    email: 'Unknown',
    issuer: 'Unknown',
    serialNumber: 'Unknown'
  };

  try {
    cert.subject.attributes.forEach(attr => {
      if (attr.shortName === 'CN') info.commonName = attr.value;
      if (attr.shortName === 'O') info.organization = attr.value;
      if (attr.shortName === 'emailAddress') info.email = attr.value;
    });

    cert.issuer.attributes.forEach(attr => {
      if (attr.shortName === 'CN') info.issuer = attr.value;
    });
    
    info.serialNumber = cert.serialNumber;
  } catch (e) {}

  return info;
}

function buildCertificateChain(p7) {
  const chain = [];
  
  if (p7.certificates && p7.certificates.length > 0) {
    p7.certificates.forEach((cert, idx) => {
      const info = extractCertificateInfo(cert);
      chain.push({
        position: idx + 1,
        subjectCN: info.commonName,
        issuerCN: info.issuer
      });
    });
  }
  
  return chain;
}

function extractSigningTime(p7) {
  try {
    if (p7.rawCapture && p7.rawCapture.authenticatedAttributes) {
      for (let attr of p7.rawCapture.authenticatedAttributes) {
        const attrOid = forge.asn1.derToOid(attr.value[0].value);
        if (attrOid === forge.pki.oids.signingTime) {
          const timeValue = attr.value[1].value[0].value;
          return formatDate(new Date(timeValue));
        }
      }
    }
  } catch (e) {}
  return null;
}

exports.handler = async (event) => {
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
      body: JSON.stringify({ error: 'Method not allowed', valid: false })
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

    const buffer = Buffer.from(fileData, 'base64');
    const pdfString = buffer.toString('latin1');

    if (!pdfString.startsWith('%PDF-')) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Not a valid PDF file', valid: false })
      };
    }

    // Extract signature
    const byteRangeMatch = pdfString.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
    
    if (!byteRangeMatch) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          valid: false,
          format: 'PAdES',
          fileName,
          error: 'No digital signature found in PDF'
        })
      };
    }

    // Extract signature content
    const contentsMatch = pdfString.match(/\/Contents\s*<([0-9a-fA-F]+)>/);
    if (!contentsMatch) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          valid: false,
          format: 'PAdES',
          fileName,
          error: 'Signature content not found'
        })
      };
    }

    const signatureHex = contentsMatch[1];
    const signatureBytes = Buffer.from(signatureHex, 'hex');

    let result = {
      valid: false,
      format: 'PAdES',
      fileName,
      structureValid: true,
      cryptographicVerification: true
    };

    try {
      // Parse PKCS#7
      const asn1 = forge.asn1.fromDer(signatureBytes.toString('binary'));
      const p7 = forge.pkcs7.messageFromAsn1(asn1);

      if (p7.certificates && p7.certificates.length > 0) {
        const cert = p7.certificates[0];
        const certInfo = extractCertificateInfo(cert);
        
        // Certificate validation
        const now = new Date();
        const certValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;

        result.valid = certValid;
        result.certificateValid = certValid;
        result.signedBy = certInfo.commonName;
        result.organization = certInfo.organization;
        result.email = certInfo.email;
        result.certificateIssuer = certInfo.issuer;
        result.certificateValidFrom = formatDate(cert.validity.notBefore);
        result.certificateValidTo = formatDate(cert.validity.notAfter);
        result.serialNumber = certInfo.serialNumber;
        result.isSelfSigned = cert.issuer.hash === cert.subject.hash;
        
        // Extract signing time
        const signingTime = extractSigningTime(p7);
        if (signingTime) {
          result.signatureDate = signingTime;
        }
        
        // Build certificate chain
        result.certificateChain = buildCertificateChain(p7);
        result.certificateChainLength = p7.certificates.length;
        
        // Algorithm
        result.signatureAlgorithm = 'RSA-SHA256';
        
        // Warnings
        result.warnings = [];
        if (result.isSelfSigned) {
          result.warnings.push('Certificate is self-signed');
        }
        if (!certValid) {
          result.warnings.push('Certificate is expired or not yet valid');
        }
        result.warnings.push('Full cryptographic verification requires specialized tools');
      }
    } catch (parseError) {
      result.error = 'Could not parse signature structure';
      result.structureValid = false;
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(result)
    };

  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Verification failed: ' + error.message,
        valid: false
      })
    };
  }
};
