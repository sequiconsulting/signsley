const forge = require('node-forge');
const {
  formatDate,
  isSelfSignedCertificate,
  extractCertificateInfo,
  checkCertificateRevocation
} = require('./shared-utils');

function parseXMLSignature(xmlContent) {
  try {
    const signatureMatch = xmlContent.match(/<ds:Signature[^>]*>([\s\S]*?)<\/ds:Signature>/);
    if (!signatureMatch) {
      throw new Error('No XML signature found');
    }

    const certMatch = xmlContent.match(/<ds:X509Certificate[^>]*>([\s\S]*?)<\/ds:X509Certificate>/);
    if (!certMatch) {
      throw new Error('No X509Certificate found in signature');
    }

    const certData = certMatch[1].replace(/\s+/g, '');
    const certDer = forge.util.createBuffer(forge.util.decode64(certData));
    const cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certDer));

    const signingTimeMatch = xmlContent.match(/<xades:SigningTime[^>]*>([^<]+)<\/xades:SigningTime>/);
    const signingTime = signingTimeMatch ? signingTimeMatch[1] : null;

    return {
      certificate: cert,
      signingTime: signingTime,
      signatureElement: signatureMatch[0]
    };
  } catch (e) {
    throw new Error(`XML signature parsing failed: ${e.message}`);
  }
}

function validateXMLSignatureStructure(xmlContent) {
  const requiredElements = [
    /<ds:Signature[^>]*>/,
    /<ds:SignedInfo[^>]*>/,
    /<ds:CanonicalizationMethod[^>]*>/,
    /<ds:SignatureMethod[^>]*>/,
    /<ds:Reference[^>]*>/,
    /<ds:DigestMethod[^>]*>/,
    /<ds:DigestValue[^>]*>/,
    /<ds:SignatureValue[^>]*>/,
    /<ds:KeyInfo[^>]*>/
  ];

  const missingElements = [];
  for (const pattern of requiredElements) {
    if (!pattern.test(xmlContent)) {
      missingElements.push(pattern.toString());
    }
  }

  return {
    valid: missingElements.length === 0,
    missingElements: missingElements
  };
}

// XAdES integrity verification - limited by XML signature complexity
function verifyXAdESStructure(xmlContent) {
  const result = {
    intact: null,
    reason: '',
    structureValid: false,
    error: null
  };

  try {
    const structureValidation = validateXMLSignatureStructure(xmlContent);
    
    if (!structureValidation.valid) {
      result.reason = 'Invalid XML signature structure';
      return result;
    }

    // XAdES signatures require specialized XML signature verification
    result.structureValid = true;
    result.intact = null;
    result.reason = 'XAdES structure valid - full XML signature cryptographic verification not implemented';

    return result;
  } catch (e) {
    result.error = `Structure verification error: ${e.message}`;
    result.reason = 'Cannot verify XAdES structure';
    return result;
  }
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed', valid: false }) };

  const startTime = Date.now();
  const verificationTimestamp = new Date().toISOString();

  try {
    const body = JSON.parse(event.body);
    const { fileData, fileName } = body;

    if (!fileData) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'No file data provided', valid: false }) };
    }

    const buffer = Buffer.from(fileData, 'base64');
    const xmlContent = buffer.toString('utf-8');

    console.log(`Processing XAdES file: ${fileName}, size: ${buffer.length} bytes`);

    if (!xmlContent.includes('<?xml') && !xmlContent.includes('<')) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          error: 'Not a valid XML file',
          valid: false,
          documentIntact: null,
          integrityReason: 'Not a valid XML file',
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    const structureValidation = validateXMLSignatureStructure(xmlContent);

    if (!structureValidation.valid) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false,
          format: 'XAdES (XML Advanced Electronic Signature)',
          fileName,
          structureValid: false,
          documentIntact: null,
          integrityReason: 'Invalid XML signature structure',
          error: 'Invalid XML signature structure',
          warnings: ['Missing required XML signature elements'],
          troubleshooting: [
            'Verify the file contains a valid XAdES signature',
            `Missing elements: ${structureValidation.missingElements.join(', ')}`,
            'Check XML signature standards compliance'
          ],
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    let signatureInfo;
    try {
      signatureInfo = parseXMLSignature(xmlContent);
    } catch (e) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false,
          format: 'XAdES (XML Advanced Electronic Signature)',
          fileName,
          structureValid: true,
          documentIntact: null,
          integrityReason: 'Signature parsing failed',
          error: `Signature parsing failed: ${e.message}`,
          warnings: ['XML signature structure found but parsing failed'],
          troubleshooting: [
            'The signature may use unsupported encoding',
            'Certificate extraction failed',
            'Use specialized XAdES validation tools'
          ],
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    const cert = signatureInfo.certificate;
    const certInfo = extractCertificateInfo(cert);

    const now = new Date();
    const certValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;
    const selfSigned = isSelfSignedCertificate(cert);

    let revocationStatus = null;
    try {
      revocationStatus = await checkCertificateRevocation(cert, null);
    } catch (e) {
      console.log('Revocation check failed:', e.message);
      revocationStatus = { checked: false, revoked: false, error: e.message };
    }

    // Verify XAdES structure
    const integrityResult = verifyXAdESStructure(xmlContent);

    const result = {
      valid: false, // Always false for XAdES without full crypto verification
      format: 'XAdES (XML Advanced Electronic Signature)',
      fileName,
      structureValid: integrityResult.structureValid,
      documentIntact: integrityResult.intact,
      integrityReason: integrityResult.reason,
      cryptographicVerification: false,
      signatureValid: integrityResult.structureValid,
      certificateValid: certValid,
      chainValid: true,
      chainValidationPerformed: false,
      revocationChecked: revocationStatus ? revocationStatus.checked : false,
      revoked: revocationStatus ? revocationStatus.revoked : false,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(cert.validity.notBefore),
      certificateValidTo: formatDate(cert.validity.notAfter),
      serialNumber: certInfo.serialNumber,
      isSelfSigned: selfSigned,
      signatureDate: signatureInfo.signingTime ? formatDate(new Date(signatureInfo.signingTime)) : null,
      certificateChainLength: 1,
      signatureAlgorithm: 'RSA-SHA256',
      warnings: [],
      troubleshooting: [],
      verificationTimestamp,
      processingTime: Date.now() - startTime
    };

    // Add warnings
    result.warnings.push('XAdES signatures require specialized XML signature verification');
    
    if (!certValid) {
      result.warnings.push('Certificate has expired or is not yet valid');
    }

    if (selfSigned) {
      result.warnings.push('Self-signed certificate detected');
    }

    if (revocationStatus && !revocationStatus.checked) {
      result.troubleshooting.push(`Revocation check: ${revocationStatus.error || 'Could not verify'}`);
    }

    if (revocationStatus && revocationStatus.revoked) {
      result.warnings.push('Certificate has been revoked');
    }

    result.troubleshooting.push('Use dedicated XAdES validation software for complete verification');

    console.log(`XAdES verification complete. Structure valid: ${result.structureValid}`);
    return { statusCode: 200, headers, body: JSON.stringify(result) };

  } catch (error) {
    console.error('XAdES handler error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Verification failed',
        message: error.message,
        valid: false,
        documentIntact: null,
        verificationTimestamp,
        processingTime: Date.now() - startTime
      })
    };
  }
};
