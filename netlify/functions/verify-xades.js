const { DOMParser } = require('xmldom');
const xpath = require('xpath');
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
    const result = await verifyXAdESSignature(buffer, fileName);
    
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

async function verifyXAdESSignature(xmlBuffer, fileName) {
  try {
    const xmlString = xmlBuffer.toString('utf-8');
    
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlString, 'text/xml');

    const parserError = doc.getElementsByTagName('parsererror');
    if (parserError.length > 0) {
      return {
        valid: false,
        format: 'XAdES',
        fileName: fileName,
        error: 'Invalid XML structure'
      };
    }

    const select = xpath.useNamespaces({
      'ds': 'http://www.w3.org/2000/09/xmldsig#',
      'xades': 'http://uri.etsi.org/01903/v1.3.2#'
    });

    const signatureNodes = select('//ds:Signature', doc);
    if (signatureNodes.length === 0) {
      return {
        valid: false,
        format: 'XAdES',
        fileName: fileName,
        error: 'No XML signature found'
      };
    }

    const signatureNode = signatureNodes[0];

    const signatureValueNodes = select('.//ds:SignatureValue/text()', signatureNode);
    if (signatureValueNodes.length === 0) {
      return {
        valid: false,
        format: 'XAdES',
        fileName: fileName,
        error: 'SignatureValue not found'
      };
    }

    const signatureValue = signatureValueNodes[0].data.replace(/\s/g, '');

    const certNodes = select('.//ds:X509Certificate/text()', signatureNode);
    let cert = null;
    let signerInfo = {
      commonName: 'Unknown',
      organization: 'Unknown',
      email: 'Unknown',
      issuer: 'Unknown'
    };

    if (certNodes.length > 0) {
      try {
        const certPem = '-----BEGIN CERTIFICATE-----\n' + 
                       certNodes[0].data.replace(/\s/g, '') + 
                       '\n-----END CERTIFICATE-----';
        cert = forge.pki.certificateFromPem(certPem);
        signerInfo = extractCertificateInfo(cert);
      } catch (e) {
        // Ignore
      }
    }

    let signatureDate = 'Unknown';
    const signingTimeNodes = select('.//xades:SigningTime/text()', signatureNode);
    if (signingTimeNodes.length > 0) {
      try {
        signatureDate = new Date(signingTimeNodes[0].data).toLocaleString();
      } catch (e) {
        signatureDate = signingTimeNodes[0].data;
      }
    }

    const signatureMethodNodes = select('.//ds:SignatureMethod/@Algorithm', signatureNode);
    let signatureAlgorithm = 'RSA-SHA256';
    if (signatureMethodNodes.length > 0) {
      const alg = signatureMethodNodes[0].value;
      if (alg.includes('sha256')) signatureAlgorithm = 'RSA-SHA256';
      else if (alg.includes('sha384')) signatureAlgorithm = 'RSA-SHA384';
      else if (alg.includes('sha512')) signatureAlgorithm = 'RSA-SHA512';
      else if (alg.includes('sha1')) signatureAlgorithm = 'RSA-SHA1';
    }

    let structureValid = false;
    
    try {
      const signedInfoNodes = select('.//ds:SignedInfo', signatureNode);
      const referenceNodes = select('.//ds:Reference', signatureNode);
      
      structureValid = (
        signedInfoNodes.length > 0 &&
        referenceNodes.length > 0 &&
        signatureValueNodes.length > 0
      );
    } catch (e) {
      structureValid = false;
    }

    let certValid = true;
    let isSelfSigned = false;
    let certValidFrom = 'Unknown';
    let certValidTo = 'Unknown';
    let serialNumber = 'Unknown';

    if (cert) {
      const now = new Date();
      certValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;
      isSelfSigned = cert.issuer.hash === cert.subject.hash;
      certValidFrom = cert.validity.notBefore.toLocaleDateString();
      certValidTo = cert.validity.notAfter.toLocaleDateString();
      serialNumber = cert.serialNumber;
    }

    const xadesLevel = determineXAdESLevel(doc, select);
    
    const result = {
      valid: structureValid && certValid && cert !== null,
      structureValid: structureValid,
      format: `XAdES (XML Advanced Electronic Signature) - ${xadesLevel}`,
      fileName: fileName,
      cryptographicVerification: false,
      signatureValid: null,
      certificateValid: certValid,
      signedBy: signerInfo.commonName,
      organization: signerInfo.organization,
      email: signerInfo.email,
      signatureDate: signatureDate,
      signatureAlgorithm: signatureAlgorithm,
      certificateIssuer: signerInfo.issuer,
      certificateValidFrom: certValidFrom,
      certificateValidTo: certValidTo,
      serialNumber: serialNumber,
      isSelfSigned: isSelfSigned,
      warnings: []
    };

    result.warnings.push('Structure-only validation (not full cryptographic)');
    result.warnings.push('Full XAdES requires XML canonicalization');

    if (!cert) {
      result.warnings.push('No certificate found');
      result.valid = false;
    }

    if (isSelfSigned) {
      result.warnings.push('Certificate is self-signed');
    }
    
    if (!certValid && cert) {
      result.warnings.push('Certificate is expired or not yet valid');
    }

    if (!structureValid) {
      result.warnings.push('XML signature structure incomplete');
    }

    result.warnings.push('CRL/OCSP not checked');

    result.details = 'Validated: XML structure, certificate parsing, expiry. NOT: signature cryptography, canonicalization, digests.';

    return result;

  } catch (error) {
    return {
      valid: false,
      format: 'XAdES',
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

function determineXAdESLevel(doc, select) {
  const hasQualifyingProperties = select('//xades:QualifyingProperties', doc).length > 0;
  const hasSignatureTimeStamp = select('//xades:SignatureTimeStamp', doc).length > 0;
  const hasArchiveTimeStamp = select('//xades:ArchiveTimeStamp', doc).length > 0;
  const hasCertificateValues = select('//xades:CertificateValues', doc).length > 0;
  const hasRevocationValues = select('//xades:RevocationValues', doc).length > 0;

  if (hasArchiveTimeStamp) {
    return 'XAdES-A (Archival)';
  } else if (hasCertificateValues && hasRevocationValues && hasSignatureTimeStamp) {
    return 'XAdES-LT (Long Term)';
  } else if (hasSignatureTimeStamp) {
    return 'XAdES-T (Timestamp)';
  } else if (hasQualifyingProperties) {
    return 'XAdES-BES (Basic)';
  } else {
    return 'XMLDSig (Basic XML Signature)';
  }
}
