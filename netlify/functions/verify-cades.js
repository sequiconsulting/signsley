const forge = require('node-forge');
const {
  formatDate,
  isSelfSignedCertificate,
  extractCertificateInfo,
  checkCertificateRevocation,
  selectSignerCertificate,
  buildCertificateChain,
  validateCertificateChain,
  validateCertificateAtSigningTime
} = require('./shared-utils');

function tryParseCAdES(buffer) {
  const strategies = [
    () => parseDirectPKCS7(buffer),
    () => parseWithStripping(buffer),
    () => parseFromHex(buffer),
    () => parseWithRelaxedValidation(buffer)
  ];

  for (const strategy of strategies) {
    try {
      const result = strategy();
      if (result && result.certificates && result.certificates.length > 0) {
        return result;
      }
    } catch {}
  }

  return null;
}

function parseDirectPKCS7(buffer) {
  const der = forge.util.createBuffer(buffer.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function parseWithStripping(buffer) {
  let cleaned = buffer;
  while (cleaned.length > 0 && cleaned[0] === 0) {
    cleaned = cleaned.slice(1);
  }
  const der = forge.util.createBuffer(cleaned.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function parseFromHex(buffer) {
  const str = buffer.toString('utf8');
  if (/^[0-9a-fA-F\s]+$/.test(str.trim())) {
    const hex = str.replace(/\s+/g, '');
    const binary = Buffer.from(hex, 'hex');
    const der = forge.util.createBuffer(binary.toString('binary'));
    const asn1 = forge.asn1.fromDer(der);
    return forge.pkcs7.messageFromAsn1(asn1);
  }
  throw new Error('Not hex format');
}

function parseWithRelaxedValidation(buffer) {
  const der = forge.util.createBuffer(buffer.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function extractSigningTime(p7) {
  try {
    if (p7.rawCapture && p7.rawCapture.authenticatedAttributes) {
      for (let attr of p7.rawCapture.authenticatedAttributes) {
        const oid = forge.asn1.derToOid(attr.value[0].value);
        if (oid === forge.pki.oids.signingTime || oid === '1.2.840.113549.1.9.5') {
          const timeValue = attr.value[1].value[0].value;
          return formatDate(new Date(timeValue));
        }
      }
    }
  } catch {}
  return null;
}

function extractRawSigningTime(p7) {
  try {
    if (p7.rawCapture && p7.rawCapture.authenticatedAttributes) {
      for (let attr of p7.rawCapture.authenticatedAttributes) {
        const oid = forge.asn1.derToOid(attr.value[0].value);
        if (oid === forge.pki.oids.signingTime || oid === '1.2.840.113549.1.9.5') {
          const timeValue = attr.value[1].value[0].value;
          return new Date(timeValue);
        }
      }
    }
  } catch {}
  return null;
}

// CAdES integrity verification - limited by detached signature nature
function verifyCAdESStructure(p7) {
  const result = {
    intact: null,
    reason: '',
    structureValid: false,
    error: null
  };

  try {
    const hasCertificates = p7.certificates && p7.certificates.length > 0;
    const hasSignature = p7.rawCapture && p7.rawCapture.signature;

    if (!hasCertificates) {
      result.reason = 'No certificates found in CAdES structure';
      return result;
    }

    if (!hasSignature) {
      result.reason = 'No signature data found in CAdES structure';
      return result;
    }

    // CAdES signatures are typically detached - we can only verify structure
    result.structureValid = true;
    result.intact = null;
    result.reason = 'CAdES structure valid - content not available for cryptographic verification';

    return result;
  } catch (e) {
    result.error = `Structure verification error: ${e.message}`;
    result.reason = 'Cannot verify CAdES structure';
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
    console.log(`Processing CAdES file: ${fileName}, size: ${buffer.length} bytes`);

    const p7 = tryParseCAdES(buffer);

    if (!p7) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false,
          format: 'CAdES (CMS Advanced Electronic Signature)',
          fileName,
          structureValid: false,
          documentIntact: null,
          integrityReason: 'Unable to parse PKCS#7/CMS structure',
          error: 'Unable to parse PKCS#7/CMS structure',
          warnings: ['File does not contain a valid CAdES signature'],
          troubleshooting: ['Verify the file is a valid CAdES/PKCS#7 signature', 'Check file integrity'],
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    if (!p7.certificates || p7.certificates.length === 0) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false,
          format: 'CAdES (CMS Advanced Electronic Signature)',
          fileName,
          structureValid: true,
          documentIntact: null,
          integrityReason: 'No certificates found in signature',
          error: 'No certificates found in signature',
          warnings: ['PKCS#7 structure found but no certificates'],
          troubleshooting: ['The signature may be detached', 'Certificates may be stored separately'],
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    const rawSigningTime = extractRawSigningTime(p7);
    const signingTime = extractSigningTime(p7);
    
    const signerCert = selectSignerCertificate(p7.certificates);
    const certInfo = extractCertificateInfo(signerCert);
    const certValidation = validateCertificateAtSigningTime(signerCert, rawSigningTime);
    const chainValidation = validateCertificateChain(p7.certificates, rawSigningTime);

    let revocationStatus = null;
    try {
      const orderedChain = buildCertificateChain(p7.certificates);
      const issuerCert = orderedChain.length > 1 ?
        p7.certificates.find(c => extractCertificateInfo(c).commonName === orderedChain[1].issuer.split('CN=')[1]?.split(',')[0]) :
        (p7.certificates.length > 1 ? p7.certificates[1] : null);
      revocationStatus = await checkCertificateRevocation(signerCert, issuerCert);
    } catch (e) {
      revocationStatus = { checked: false, revoked: false, error: e.message };
    }

    // Verify CAdES structure
    const integrityResult = verifyCAdESStructure(p7);

    const certificateChain = buildCertificateChain(p7.certificates);
    const isSelfSigned = isSelfSignedCertificate(signerCert);

    // For CAdES, we cannot determine document integrity without original content
    const result = {
      valid: false, // Always false for CAdES without original content
      format: 'CAdES (CMS Advanced Electronic Signature)',
      fileName,
      structureValid: integrityResult.structureValid,
      documentIntact: integrityResult.intact,
      integrityReason: integrityResult.reason,
      cryptographicVerification: false,
      signatureValid: integrityResult.structureValid,
      certificateValid: certValidation.validAtSigningTime,
      certificateValidAtSigning: certValidation.validAtSigningTime,
      certificateExpiredSinceSigning: certValidation.expiredSinceSigning,
      certificateValidNow: certValidation.validNow,
      signingTimeUsed: signingTime,
      chainValid: chainValidation.valid,
      chainValidationPerformed: true,
      revocationChecked: revocationStatus ? revocationStatus.checked : false,
      revoked: revocationStatus ? revocationStatus.revoked : false,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(signerCert.validity.notBefore),
      certificateValidTo: formatDate(signerCert.validity.notAfter),
      serialNumber: certInfo.serialNumber,
      isSelfSigned: isSelfSigned,
      signatureDate: signingTime,
      certificateChainLength: p7.certificates.length,
      signatureAlgorithm: 'RSA-SHA256',
      certificateChain: certificateChain,
      warnings: [],
      troubleshooting: [],
      verificationTimestamp,
      processingTime: Date.now() - startTime
    };

    // Add warnings
    result.warnings.push('CAdES signatures require the original content for full cryptographic verification');
    
    if (isSelfSigned) {
      result.warnings.push('Self-signed certificate detected');
    }
    
    if (!certValidation.validAtSigningTime) {
      result.warnings.push('Certificate was not valid at signing time');
    } else if (certValidation.expiredSinceSigning) {
      result.warnings.push('Certificate expired after signing');
    }
    
    if (chainValidation.errors && chainValidation.errors.length > 0) {
      result.warnings.push(...chainValidation.errors);
    }
    
    if (revocationStatus && !revocationStatus.checked) {
      result.troubleshooting.push(`Revocation check: ${revocationStatus.error || 'Could not verify'}`);
    }
    
    if (revocationStatus && revocationStatus.revoked) {
      result.warnings.push('Certificate has been revoked');
    }

    result.troubleshooting.push('Use specialized CAdES validation software with original content for complete verification');

    console.log(`CAdES verification complete. Structure valid: ${result.structureValid}`);
    return { statusCode: 200, headers, body: JSON.stringify(result) };

  } catch (error) {
    console.error('CAdES handler error:', error);
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
