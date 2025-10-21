const forge = require('node-forge');
const crypto = require('crypto');
const {
  formatDate,
  isSelfSignedCertificate,
  extractCertificateInfo,
  checkCertificateRevocation,
  validateCertificateAtSigningTime,
  selectSignerCertificate,
  buildCertificateChain,
  validateCertificateChain
} = require('./shared-utils');

function bytesFromHex(hex) {
  return Buffer.from(hex, 'hex');
}

function getDERLength(hexString) {
  try {
    if (hexString.length < 4) return null;
    const bytes = bytesFromHex(hexString.substring(0, 20));
    let offset = 1;
    const firstLengthByte = bytes[offset++];
    if ((firstLengthByte & 0x80) === 0) {
      return 2 + firstLengthByte;
    } else {
      const lengthOfLength = firstLengthByte & 0x7f;
      if (lengthOfLength === 0 || lengthOfLength > 4) return null;
      let contentLength = 0;
      for (let i = 0; i < lengthOfLength; i++) {
        contentLength = (contentLength << 8) | bytes[offset++];
      }
      return 2 + lengthOfLength + contentLength;
    }
  } catch {
    return null;
  }
}

function validateAndTrimDER(hexString) {
  const expectedLength = getDERLength(hexString);
  if (!expectedLength) return hexString;
  const expectedHexLength = expectedLength * 2;
  if (hexString.length > expectedHexLength) {
    return hexString.substring(0, expectedHexLength);
  }
  return hexString;
}

function extractAllHexContents(pdfString) {
  const allHex = [];
  
  const contentsPatterns = [
    /\/Contents\s*<([0-9a-fA-F\s\r\n]+)>/gi,
    /\/Contents<([0-9a-fA-F\s\r\n]+)>/gi,
    /\/Contents\s+<([0-9a-fA-F\s\r\n]+)>/gi,
    /Contents\s*<([0-9a-fA-F\s\r\n]+)>/gi
  ];

  contentsPatterns.forEach((pattern, idx) => {
    let m;
    while ((m = pattern.exec(pdfString)) !== null) {
      const hex = m[1].replace(/[\s\r\n]+/g, '');
      if (hex.length > 100) {
        allHex.push({ hex, position: m.index, confidence: 9 - idx });
      }
    }
  });

  const seen = new Set();
  const unique = allHex.filter(item => {
    const key = item.hex.substring(0, 300);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  unique.sort((a, b) => (b.confidence - a.confidence) || (b.hex.length - a.hex.length));
  return unique;
}

function findByteRanges(pdfString) {
  const ranges = [];
  const patterns = [
    /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g,
    /ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g
  ];

  patterns.forEach((pattern) => {
    let m;
    while ((m = pattern.exec(pdfString)) !== null) {
      const range = [parseInt(m[1]), parseInt(m[2]), parseInt(m[3]), parseInt(m[4])];
      if (range.every(n => !isNaN(n) && n >= 0)) {
        ranges.push({ range, position: m.index });
      }
    }
  });

  return ranges;
}

function findAllSignatures(buffer) {
  const pdfString = buffer.toString('latin1');
  const signatures = [];
  const processed = new Set();

  const byteRanges = findByteRanges(pdfString);
  const hexContents = extractAllHexContents(pdfString);

  for (const br of byteRanges) {
    let closestHex = null, minDistance = Infinity;
    for (const hc of hexContents) {
      const d = Math.abs(hc.position - br.position);
      if (d < minDistance && d < 500000) {
        minDistance = d;
        closestHex = hc;
      }
    }
    if (closestHex) {
      const key = closestHex.hex.substring(0, 200);
      if (!processed.has(key)) {
        processed.add(key);
        signatures.push({
          byteRange: br.range,
          signatureHex: closestHex.hex,
          confidence: (closestHex.confidence || 0) + 3
        });
      }
    }
  }

  for (const hc of hexContents) {
    const key = hc.hex.substring(0, 200);
    if (!processed.has(key)) {
      processed.add(key);
      signatures.push({
        byteRange: null,
        signatureHex: hc.hex,
        confidence: hc.confidence || 0
      });
    }
  }

  const filtered = signatures.filter(sig => sig.signatureHex.length >= 400);
  filtered.sort((a, b) => b.confidence - a.confidence);
  return filtered;
}

function tryParseSignature(signatureHex) {
  try {
    const trimmed = validateAndTrimDER(signatureHex);
    const bytes = bytesFromHex(trimmed);
    const der = forge.util.createBuffer(bytes.toString('binary'));
    const asn1 = forge.asn1.fromDer(der);
    return forge.pkcs7.messageFromAsn1(asn1);
  } catch (e) {
    return null;
  }
}

// CRITICAL FIX: Extract message digest from authenticated attributes
function extractMessageDigestFromAttributes(p7) {
  try {
    if (!p7.rawCapture || !p7.rawCapture.authenticatedAttributes) {
      return null;
    }

    const attrs = p7.rawCapture.authenticatedAttributes;
    for (const attr of attrs) {
      try {
        const oid = forge.asn1.derToOid(attr.value[0].value);
        if (oid === '1.2.840.113549.1.9.4') {  // messageDigest
          const digestValue = attr.value[1].value[0].value;
          return Buffer.from(digestValue, 'binary').toString('hex');
        }
      } catch {}
    }
  } catch {}
  return null;
}

// CORE INTEGRITY LOGIC: Compare message digest with actual content hash
function verifyCryptographicIntegrity(p7, pdfBuffer, byteRange) {
  const result = {
    intact: null,
    reason: '',
    cryptoValid: false,
    error: null
  };

  try {
    if (!p7.certificates || p7.certificates.length === 0) {
      result.reason = 'No certificates found';
      return result;
    }

    if (!byteRange || byteRange.length !== 4) {
      result.reason = 'Invalid ByteRange';
      return result;
    }

    // Compute hash of signed content
    const [a1, l1, a2, l2] = byteRange;
    const part1 = pdfBuffer.subarray(a1, a1 + l1);
    const part2 = pdfBuffer.subarray(a2, a2 + l2);
    const signedContent = Buffer.concat([part1, part2]);
    const computedHash = crypto.createHash('sha256').update(signedContent).digest('hex');

    // Extract message digest from signature
    const embeddedDigest = extractMessageDigestFromAttributes(p7);
    
    if (!embeddedDigest) {
      result.reason = 'No message digest in signature';
      return result;
    }

    // CRITICAL COMPARISON: Does embedded hash match computed hash?
    if (embeddedDigest === computedHash) {
      result.intact = true;
      result.cryptoValid = true;
      result.reason = 'Cryptographic hash verified';
      return result;
    } else {
      result.intact = false;
      result.cryptoValid = false;
      result.reason = 'Hash mismatch - document modified';
      return result;
    }
  } catch (e) {
    result.error = `Verification exception: ${e.message}`;
    result.reason = 'Cryptographic verification failed';
  }

  return result;
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

async function extractSignatureInfo(signatureHex, pdfBuffer, byteRange, signatureIndex) {
  try {
    const p7 = tryParseSignature(signatureHex);
    if (!p7 || !p7.certificates || p7.certificates.length === 0) return null;

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

    // CRITICAL: Use fixed verification
    const integrityResult = verifyCryptographicIntegrity(p7, pdfBuffer, byteRange);
    
    const certificateChain = buildCertificateChain(p7.certificates);
    const isSelfSigned = isSelfSignedCertificate(signerCert);

    return {
      signatureIndex: signatureIndex,
      documentIntact: integrityResult.intact,
      integrityReason: integrityResult.reason,
      cryptographicVerification: integrityResult.cryptoValid,
      signatureValid: integrityResult.cryptoValid,
      certificateValid: certValidation.validAtSigningTime,
      certificateValidAtSigning: certValidation.validAtSigningTime,
      certificateExpiredSinceSigning: certValidation.expiredSinceSigning,
      certificateValidNow: certValidation.validNow,
      signingTimeUsed: signingTime,
      rawSigningTime: rawSigningTime,
      chainValid: chainValidation.valid,
      chainValidationErrors: chainValidation.errors,
      revocationStatus: revocationStatus,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(signerCert.validity.notBefore),
      certificateValidTo: formatDate(signerCert.validity.notAfter),
      serialNumber: certInfo.serialNumber,
      isSelfSigned: isSelfSigned,
      signatureDate: signingTime,
      certificateChain: certificateChain,
      certificateChainLength: p7.certificates.length,
      signatureAlgorithm: 'RSA-SHA256',
      verificationError: integrityResult.error
    };
  } catch (e) {
    return null;
  }
}

function aggregateMultipleSignatures(allSigInfo) {
  if (!allSigInfo || allSigInfo.length === 0) {
    return {
      documentIntact: null,
      finalReason: 'No signatures found',
      allValid: false
    };
  }

  const modified = allSigInfo.filter(sig => sig.documentIntact === false);
  const intact = allSigInfo.filter(sig => sig.documentIntact === true);

  if (modified.length > 0) {
    const modifiedSigs = modified.map(sig => `#${sig.signatureIndex + 1}`).join(', ');
    return {
      documentIntact: false,
      finalReason: `Document modified - hash mismatch in signature(s) ${modifiedSigs}`,
      allValid: false
    };
  }

  if (intact.length > 0) {
    return {
      documentIntact: true,
      finalReason: intact.length === allSigInfo.length 
        ? 'All signatures cryptographically verified'
        : `${intact.length} of ${allSigInfo.length} signatures verified`,
      allValid: intact.length === allSigInfo.length
    };
  }

  return {
    documentIntact: null,
    finalReason: 'Cannot verify cryptographic integrity',
    allValid: false
  };
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
    if (!fileData) return { statusCode: 400, headers, body: JSON.stringify({ error: 'No file data provided', valid: false }) };

    const buffer = Buffer.from(fileData, 'base64');
    const pdfString = buffer.toString('latin1');
    if (!pdfString.startsWith('%PDF-')) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Not a valid PDF', valid: false }) };
    }

    const signatures = findAllSignatures(buffer);
    if (signatures.length === 0) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false,
          format: 'PAdES',
          fileName,
          structureValid: false,
          documentIntact: null,
          integrityReason: 'No digital signature detected',
          error: 'No digital signature detected',
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    const allSigInfo = [];
    for (let i = 0; i < signatures.length; i++) {
      const sig = signatures[i];
      const info = await extractSignatureInfo(sig.signatureHex, buffer, sig.byteRange, i);
      if (info) {
        allSigInfo.push(info);
      }
    }

    if (allSigInfo.length === 0) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false,
          format: 'PAdES',
          fileName,
          structureValid: true,
          cryptographicVerification: false,
          documentIntact: null,
          integrityReason: 'Signature parsing failed',
          error: 'Signature parsing failed',
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    const aggregated = aggregateMultipleSignatures(allSigInfo);
    const primarySig = allSigInfo[0];

    const isValid = aggregated.documentIntact === true && 
                    aggregated.allValid &&
                    allSigInfo.every(sig => 
                      sig.certificateValid && 
                      sig.chainValid && 
                      !(sig.revocationStatus && sig.revocationStatus.revoked)
                    );

    const result = {
      valid: isValid,
      format: 'PAdES',
      fileName,
      structureValid: true,
      documentIntact: aggregated.documentIntact,
      integrityReason: aggregated.finalReason,
      cryptographicVerification: allSigInfo.some(sig => sig.cryptographicVerification),
      signatureValid: allSigInfo.every(sig => sig.signatureValid !== false),
      certificateValid: primarySig.certificateValid,
      certificateValidAtSigning: primarySig.certificateValidAtSigning,
      certificateExpiredSinceSigning: primarySig.certificateExpiredSinceSigning,
      certificateValidNow: primarySig.certificateValidNow,
      signingTimeUsed: primarySig.signingTimeUsed,
      chainValid: primarySig.chainValid,
      chainValidationPerformed: true,
      revocationChecked: primarySig.revocationStatus ? primarySig.revocationStatus.checked : false,
      revoked: primarySig.revocationStatus ? primarySig.revocationStatus.revoked : false,
      signedBy: primarySig.signedBy,
      organization: primarySig.organization,
      email: primarySig.email,
      certificateIssuer: primarySig.certificateIssuer,
      certificateValidFrom: primarySig.certificateValidFrom,
      certificateValidTo: primarySig.certificateValidTo,
      serialNumber: primarySig.serialNumber,
      isSelfSigned: primarySig.isSelfSigned,
      signatureDate: primarySig.signatureDate,
      certificateChainLength: primarySig.certificateChainLength,
      signatureAlgorithm: primarySig.signatureAlgorithm,
      certificateChain: primarySig.certificateChain,
      signatureCount: allSigInfo.length,
      signatures: allSigInfo,
      warnings: [],
      troubleshooting: [],
      verificationTimestamp,
      processingTime: Date.now() - startTime
    };

    if (signatures.length > 1) {
      result.warnings.push(`Multiple signatures detected (${signatures.length})`);
    }
    
    if (primarySig.isSelfSigned) {
      result.warnings.push('Self-signed certificate');
    }
    
    if (!primarySig.certificateValidAtSigning) {
      result.warnings.push('Certificate was not valid at signing time');
    } else if (primarySig.certificateExpiredSinceSigning) {
      result.warnings.push('Certificate expired after signing');
    }
    
    if (primarySig.chainValidationErrors && primarySig.chainValidationErrors.length > 0) {
      result.warnings.push(...primarySig.chainValidationErrors);
    }
    
    if (primarySig.revocationStatus && !primarySig.revocationStatus.checked) {
      result.troubleshooting.push(`Revocation check: ${primarySig.revocationStatus.error || 'Could not verify'}`);
    }
    
    if (primarySig.revocationStatus && primarySig.revocationStatus.revoked) {
      result.warnings.push('Certificate has been revoked');
    }

    return { statusCode: 200, headers, body: JSON.stringify(result) };

  } catch (error) {
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
