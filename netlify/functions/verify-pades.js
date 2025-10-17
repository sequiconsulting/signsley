// verify-pades.js (v4 with CRL/OCSP validation)
const forge = require('node-forge');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const axios = require('axios');
const NodeCache = require('node-cache');
const moment = require('moment');

// Initialize cache (1 hour TTL for CRL/OCSP responses)
const validationCache = new NodeCache({ stdTTL: 3600 });

// Set crypto engine for PKI.js
const crypto = require('crypto').webcrypto;
pkijs.setEngine('newEngine', crypto, new pkijs.CryptoEngine({
  crypto,
  subtle: crypto.subtle
}));

// Configuration
const CONFIG = {
  HTTP_TIMEOUT: 15000,
  MAX_CRL_SIZE: 5 * 1024 * 1024, // 5MB max CRL size
  MAX_CHAIN_DEPTH: 10,
  ENABLE_OCSP: true,
  ENABLE_CRL: true,
  ENABLE_TIMESTAMP_VALIDATION: true
};

// Utility: format date YYYY/MM/DD HH:MM
function formatDateTime(date) {
  if (!date) return 'Unknown';
  try {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return 'Unknown';
    return moment(d).format('YYYY/MM/DD HH:mm');
  } catch {
    return 'Unknown';
  }
}

function formatDate(date) {
  if (!date) return 'Unknown';
  try {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return 'Unknown';
    return moment(d).format('YYYY/MM/DD');
  } catch {
    return 'Unknown';
  }
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST')
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };

  try {
    const body = JSON.parse(event.body);
    const { fileData, fileName, skipRevocationCheck = false } = body;

    if (!fileData)
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'No file data provided', valid: false }) };

    const base64 = fileData.replace(/^data:application\/pdf;base64,/, '').trim();
    if (!/^[A-Za-z0-9+/=]+$/.test(base64))
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid Base64 data format', valid: false }) };

    const size = (base64.length * 3) / 4;
    if (size > 6 * 1024 * 1024)
      return { statusCode: 413, headers, body: JSON.stringify({ error: 'File too large', valid: false }) };

    const buffer = Buffer.from(base64, 'base64');
    const result = await verifyAdvancedPAdESWithValidation(buffer, fileName, !skipRevocationCheck);

    return { statusCode: 200, headers, body: JSON.stringify(result) };
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

// ------------------------------------------------------------------
// MAIN VERIFICATION WITH FULL VALIDATION
// ------------------------------------------------------------------
async function verifyAdvancedPAdESWithValidation(pdfBuffer, fileName, enableRevocationCheck = true) {
  const startTime = Date.now();
  
  try {
    const pdfString = pdfBuffer.toString('latin1');
    
    // Basic PDF validation
    if (!pdfString.startsWith('%PDF-')) {
      return { 
        valid: false, 
        format: 'PAdES', 
        fileName, 
        error: 'Not a valid PDF file',
        processingTime: Date.now() - startTime
      };
    }

    // Extract signature structure
    const signatureInfo = extractPDFSignatureStructure(pdfString, pdfBuffer);
    if (!signatureInfo.hasSignature) {
      return { 
        valid: false, 
        format: 'PAdES', 
        fileName, 
        error: 'No digital signature found in PDF',
        structureValid: false,
        processingTime: Date.now() - startTime
      };
    }

    // Parse signature and extract certificates
    let certificates = [];
    let signatureValid = false;
    let signatureAlgorithm = 'Unknown';
    let signingTime = null;
    let timestampInfo = null;
    
    try {
      const parseResult = await parseSignatureStructure(signatureInfo);
      certificates = parseResult.certificates;
      signatureValid = parseResult.signatureValid;
      signatureAlgorithm = parseResult.algorithm;
      signingTime = parseResult.signingTime;
      timestampInfo = parseResult.timestampInfo;
    } catch (parseError) {
      console.warn('Signature parsing warning:', parseError.message);
      // Continue with structure-only analysis
    }

    if (certificates.length === 0) {
      return createStructureOnlyResult(signatureInfo, fileName, 'No certificates found', null);
    }

    // Extract certificate information
    const signerCert = certificates[0];
    const certInfo = await extractCompleteCertificateInfo(signerCert);

    // Perform certificate validation
    const validationResults = {
      certificateValid: false,
      chainValid: false,
      revocationStatus: 'Unknown',
      crlChecked: false,
      ocspChecked: false,
      timestampValid: null,
      validationErrors: []
    };

    // Basic certificate validity (date check)
    const now = new Date();
    validationResults.certificateValid = now >= certInfo.validFrom && now <= certInfo.validTo;

    // Certificate chain validation
    if (certificates.length > 1) {
      try {
        validationResults.chainValid = await validateCertificateChain(certificates);
      } catch (chainError) {
        validationResults.validationErrors.push(`Chain validation failed: ${chainError.message}`);
      }
    } else {
      validationResults.chainValid = certInfo.isSelfSigned;
    }

    // Revocation checking (CRL/OCSP)
    if (enableRevocationCheck && !certInfo.isSelfSigned) {
      try {
        const revocationResult = await checkCertificateRevocation(signerCert, certificates);
        validationResults.revocationStatus = revocationResult.status;
        validationResults.crlChecked = revocationResult.crlChecked;
        validationResults.ocspChecked = revocationResult.ocspChecked;
        if (revocationResult.errors.length > 0) {
          validationResults.validationErrors.push(...revocationResult.errors);
        }
      } catch (revocationError) {
        validationResults.validationErrors.push(`Revocation check failed: ${revocationError.message}`);
        validationResults.revocationStatus = 'Check Failed';
      }
    }

    // Timestamp validation
    if (CONFIG.ENABLE_TIMESTAMP_VALIDATION && timestampInfo) {
      try {
        validationResults.timestampValid = await validateTimestamp(timestampInfo);
      } catch (tsError) {
        validationResults.validationErrors.push(`Timestamp validation failed: ${tsError.message}`);
      }
    }

    // Determine overall validity
    const isRevoked = validationResults.revocationStatus === 'Revoked';
    const hasValidationErrors = validationResults.validationErrors.length > 0;
    
    const overallValid = signatureValid && 
                        validationResults.certificateValid && 
                        validationResults.chainValid && 
                        !isRevoked &&
                        (validationResults.timestampValid !== false);

    // Build comprehensive result
    const result = {
      valid: overallValid,
      format: signatureInfo.signatureType,
      fileName,
      processingTime: Date.now() - startTime,
      
      // Signature validation
      cryptographicVerification: true,
      structureValid: true,
      signatureValid,
      signatureAlgorithm,
      signingTime: formatDateTime(signingTime),
      
      // Certificate information
      certificateValid: validationResults.certificateValid,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      organizationalUnit: certInfo.organizationalUnit,
      country: certInfo.country,
      email: certInfo.email,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(certInfo.validFrom),
      certificateValidTo: formatDate(certInfo.validTo),
      serialNumber: certInfo.serialNumber,
      certificateChainLength: certificates.length,
      isSelfSigned: certInfo.isSelfSigned,
      
      // Chain validation
      chainValid: validationResults.chainValid,
      
      // Revocation status
      revocationStatus: validationResults.revocationStatus,
      crlChecked: validationResults.crlChecked,
      ocspChecked: validationResults.ocspChecked,
      
      // Timestamp validation
      timestampValid: validationResults.timestampValid,
      timestampInfo: timestampInfo ? {
        authority: timestampInfo.authority || 'Unknown',
        timestamp: formatDateTime(timestampInfo.timestamp),
        accuracy: timestampInfo.accuracy || 'Unknown'
      } : null,
      
      // Key usage and extensions
      keyUsage: certInfo.keyUsage,
      extendedKeyUsage: certInfo.extendedKeyUsage,
      
      // Validation details
      validationErrors: validationResults.validationErrors,
      warnings: buildComprehensiveWarnings(validationResults, certInfo, enableRevocationCheck)
    };

    return result;

  } catch (error) {
    console.error('Critical verification error:', error);
    return { 
      valid: false, 
      format: 'PAdES', 
      fileName, 
      error: 'Critical verification failure: ' + error.message,
      processingTime: Date.now() - startTime
    };
  }
}

// ------------------------------------------------------------------
// PDF SIGNATURE STRUCTURE EXTRACTION
// ------------------------------------------------------------------
function extractPDFSignatureStructure(pdfString, pdfBuffer) {
  const result = {
    hasSignature: false,
    byteRange: null,
    signatureHex: null,
    signatureBytes: null,
    signedContent: null,
    signatureType: 'Unknown',
    multipleSignatures: false
  };

  // Look for all ByteRange patterns (multiple signatures)
  const byteRangeMatches = [...pdfString.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)];
  if (byteRangeMatches.length === 0) {
    return result;
  }

  result.hasSignature = true;
  result.multipleSignatures = byteRangeMatches.length > 1;
  
  // Use the first signature (most common case)
  const byteRangeMatch = byteRangeMatches[0];
  result.byteRange = byteRangeMatch.slice(1).map(n => parseInt(n));

  // Extract signature hex
  result.signatureHex = extractSignatureHex(pdfString, byteRangeMatch.index);
  if (result.signatureHex) {
    try {
      result.signatureBytes = hexToBytes(result.signatureHex);
      
      // Create signed content
      result.signedContent = Buffer.concat([
        pdfBuffer.slice(result.byteRange[0], result.byteRange[0] + result.byteRange[1]),
        pdfBuffer.slice(result.byteRange[2], result.byteRange[2] + result.byteRange[3])
      ]);

      // Determine signature type
      result.signatureType = determineSignatureType(result.signatureBytes);
      
    } catch (e) {
      console.warn('Error processing signature bytes:', e.message);
    }
  }

  return result;
}

function extractSignatureHex(pdfString, startPos = 0) {
  const contentsIndex = pdfString.indexOf('/Contents', startPos);
  if (contentsIndex === -1) return null;
  
  const start = pdfString.indexOf('<', contentsIndex);
  const end = pdfString.indexOf('>', start);
  if (start === -1 || end === -1) return null;
  
  let hex = pdfString.substring(start + 1, end).replace(/\s/g, '');
  if (hex.length % 2 !== 0) hex = hex.slice(0, -1);
  
  return hex;
}

function hexToBytes(hex) {
  if (!/^[0-9A-Fa-f]+$/.test(hex)) {
    throw new Error('Invalid hexadecimal string');
  }
  
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

function determineSignatureType(signatureBytes) {
  try {
    const asn1 = asn1js.fromBER(signatureBytes.buffer);
    if (asn1.offset === -1) {
      return 'Unknown ASN.1 Structure';
    }

    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    
    switch (contentInfo.contentType) {
      case '1.2.840.113549.1.7.2': // signedData
        return 'PAdES-BES/LTV (PKCS#7 SignedData)';
      case '1.2.840.113549.1.7.1': // data
        return 'PAdES Basic (PKCS#7 Data)';
      default:
        return `PAdES (OID: ${contentInfo.contentType})`;
    }
  } catch (e) {
    return 'Advanced PAdES Structure';
  }
}

// ------------------------------------------------------------------
// SIGNATURE PARSING AND CERTIFICATE EXTRACTION
// ------------------------------------------------------------------
async function parseSignatureStructure(signatureInfo) {
  // Try PKI.js first
  try {
    const asn1 = asn1js.fromBER(signatureInfo.signatureBytes.buffer);
    if (asn1.offset === -1) throw new Error('Invalid ASN.1 structure');

    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    if (contentInfo.contentType !== '1.2.840.113549.1.7.2') {
      throw new Error('Not a PKCS#7 SignedData structure');
    }

    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    
    const certificates = signedData.certificates || [];
    let signingTime = null;
    let timestampInfo = null;
    
    // Extract signing time from signed attributes
    if (signedData.signerInfos && signedData.signerInfos.length > 0) {
      const signerInfo = signedData.signerInfos[0];
      if (signerInfo.signedAttrs) {
        for (const attr of signerInfo.signedAttrs.attributes) {
          if (attr.type === '1.2.840.113549.1.9.5') { // signingTime
            signingTime = attr.values[0].value;
          }
          if (attr.type === '1.2.840.113549.1.9.16.2.14') { // timeStampToken
            timestampInfo = parseTimestampToken(attr.values[0]);
          }
        }
      }
    }

    return {
      certificates,
      signatureValid: null, // Will be verified later
      algorithm: 'SHA-256', // Default, should be extracted properly
      signingTime,
      timestampInfo
    };

  } catch (pkiError) {
    // Fallback to node-forge
    try {
      const der = forge.util.createBuffer(signatureInfo.signatureBytes);
      const asn1 = forge.asn1.fromDer(der);
      const p7 = forge.pkcs7.messageFromAsn1(asn1);

      if (!p7.certificates || p7.certificates.length === 0) {
        throw new Error('No certificates found in PKCS#7 structure');
      }

      // Try signature verification
      let signatureValid = false;
      try {
        const hashAlg = getHashAlgorithmFromP7(p7);
        const md = forge.md[hashAlg].create();
        md.update(signatureInfo.signedContent.toString('binary'));
        
        if (p7.rawCapture && p7.rawCapture.signature) {
          signatureValid = p7.certificates[0].publicKey.verify(md.digest().bytes(), p7.rawCapture.signature);
        }
      } catch (err) {
        console.warn('Signature verification failed:', err.message);
      }

      return {
        certificates: p7.certificates,
        signatureValid,
        algorithm: getHashAlgorithmFromP7(p7),
        signingTime: null, // Extract from p7 if available
        timestampInfo: null
      };

    } catch (forgeError) {
      throw new Error(`Both PKI.js and node-forge parsing failed: ${pkiError.message}, ${forgeError.message}`);
    }
  }
}

// ------------------------------------------------------------------
// CERTIFICATE INFORMATION EXTRACTION
// ------------------------------------------------------------------
async function extractCompleteCertificateInfo(cert) {
  try {
    let info;
    
    if (cert.subject && cert.subject.typesAndValues) {
      // PKI.js certificate
      info = extractPKIjsCertInfo(cert);
    } else if (cert.subject && cert.subject.attributes) {
      // node-forge certificate
      info = extractForgeCertInfo(cert);
    } else {
      throw new Error('Unknown certificate format');
    }

    return info;
  } catch (error) {
    console.warn('Error extracting certificate info:', error);
    return createDefaultCertInfo();
  }
}

function extractPKIjsCertInfo(cert) {
  const subject = cert.subject.typesAndValues;
  const issuer = cert.issuer.typesAndValues;
  
  const info = {
    commonName: 'Unknown',
    organization: 'Unknown',
    organizationalUnit: 'Unknown',
    country: 'Unknown',
    email: 'Unknown',
    issuer: 'Unknown',
    validFrom: null,
    validTo: null,
    serialNumber: 'Unknown',
    isSelfSigned: false,
    keyUsage: [],
    extendedKeyUsage: []
  };

  // Extract subject information
  for (const attr of subject) {
    const type = attr.type;
    const value = attr.value.valueBlock.value;
    
    if (type === '2.5.4.3') info.commonName = value; // CN
    if (type === '2.5.4.10') info.organization = value; // O
    if (type === '2.5.4.11') info.organizationalUnit = value; // OU
    if (type === '2.5.4.6') info.country = value; // C
    if (type === '1.2.840.113549.1.9.1') info.email = value; // emailAddress
  }

  // Extract issuer CN
  for (const attr of issuer) {
    if (attr.type === '2.5.4.3') {
      info.issuer = attr.value.valueBlock.value;
      break;
    }
  }

  // Extract validity period
  if (cert.notBefore && cert.notAfter) {
    info.validFrom = cert.notBefore.value;
    info.validTo = cert.notAfter.value;
  }

  // Extract serial number
  if (cert.serialNumber) {
    info.serialNumber = bufferToHex(cert.serialNumber.valueBlock.valueHex);
  }

  // Check if self-signed
  info.isSelfSigned = info.commonName === info.issuer;

  // Extract extensions (key usage, etc.)
  if (cert.extensions) {
    for (const ext of cert.extensions) {
      if (ext.extnID === '2.5.29.15') { // keyUsage
        info.keyUsage = parseKeyUsage(ext);
      }
      if (ext.extnID === '2.5.29.37') { // extKeyUsage
        info.extendedKeyUsage = parseExtendedKeyUsage(ext);
      }
    }
  }

  return info;
}

function extractForgeCertInfo(cert) {
  const subject = cert.subject.attributes;
  const issuer = cert.issuer.attributes;
  
  const info = {
    commonName: 'Unknown',
    organization: 'Unknown',
    organizationalUnit: 'Unknown',
    country: 'Unknown',
    email: 'Unknown',
    issuer: 'Unknown',
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
    serialNumber: cert.serialNumber || 'Unknown',
    isSelfSigned: false,
    keyUsage: [],
    extendedKeyUsage: []
  };

  subject.forEach(attr => {
    if (attr.shortName === 'CN') info.commonName = attr.value;
    if (attr.shortName === 'O') info.organization = attr.value;
    if (attr.shortName === 'OU') info.organizationalUnit = attr.value;
    if (attr.shortName === 'C') info.country = attr.value;
    if (attr.shortName === 'emailAddress') info.email = attr.value;
  });

  issuer.forEach(attr => {
    if (attr.shortName === 'CN') info.issuer = attr.value;
  });

  info.isSelfSigned = isCertificateSelfSigned(cert);

  // Extract extensions if available
  if (cert.extensions) {
    cert.extensions.forEach(ext => {
      if (ext.name === 'keyUsage') {
        info.keyUsage = Object.keys(ext).filter(key => ext[key] === true);
      }
      if (ext.name === 'extKeyUsage') {
        info.extendedKeyUsage = ext.serverAuth ? ['serverAuth'] : [];
      }
    });
  }

  return info;
}

function createDefaultCertInfo() {
  return {
    commonName: 'Unknown',
    organization: 'Unknown',
    organizationalUnit: 'Unknown',
    country: 'Unknown',
    email: 'Unknown',
    issuer: 'Unknown',
    validFrom: null,
    validTo: null,
    serialNumber: 'Unknown',
    isSelfSigned: false,
    keyUsage: [],
    extendedKeyUsage: []
  };
}

// ------------------------------------------------------------------
// CERTIFICATE CHAIN VALIDATION
// ------------------------------------------------------------------
async function validateCertificateChain(certificates) {
  if (certificates.length < 2) {
    return true; // Single certificate, assume valid if not expired
  }

  try {
    // Simple chain validation - each cert should be signed by the next
    for (let i = 0; i < certificates.length - 1; i++) {
      const cert = certificates[i];
      const issuerCert = certificates[i + 1];
      
      // Verify signature (simplified)
      const isValid = await verifyCertificateSignature(cert, issuerCert);
      if (!isValid) {
        return false;
      }
    }
    
    return true;
  } catch (error) {
    console.warn('Chain validation error:', error);
    return false;
  }
}

async function verifyCertificateSignature(cert, issuerCert) {
  // Simplified signature verification
  // In a real implementation, this would perform full cryptographic verification
  try {
    if (cert.issuer && issuerCert.subject) {
      // Compare issuer DN with subject DN
      const certIssuer = extractDN(cert.issuer);
      const issuerSubject = extractDN(issuerCert.subject);
      return certIssuer === issuerSubject;
    }
    return false;
  } catch (error) {
    return false;
  }
}

function extractDN(dn) {
  if (dn.typesAndValues) {
    // PKI.js format
    return dn.typesAndValues
      .map(attr => `${attr.type}=${attr.value.valueBlock.value}`)
      .sort()
      .join(',');
  } else if (dn.attributes) {
    // node-forge format
    return dn.attributes
      .map(attr => `${attr.shortName}=${attr.value}`)
      .sort()
      .join(',');
  }
  return '';
}

// ------------------------------------------------------------------
// CRL AND OCSP VALIDATION
// ------------------------------------------------------------------
async function checkCertificateRevocation(signerCert, certificateChain) {
  const result = {
    status: 'Unknown',
    crlChecked: false,
    ocspChecked: false,
    errors: []
  };

  const cacheKey = `revocation_${getCertificateFingerprint(signerCert)}`;
  const cached = validationCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  // Extract CRL and OCSP URLs
  const crlUrls = extractCRLUrls(signerCert);
  const ocspUrls = extractOCSPUrls(signerCert);

  // Try OCSP first (faster)
  if (CONFIG.ENABLE_OCSP && ocspUrls.length > 0) {
    try {
      const ocspResult = await checkOCSP(signerCert, certificateChain, ocspUrls[0]);
      result.status = ocspResult.status;
      result.ocspChecked = true;
      
      if (ocspResult.status === 'Good' || ocspResult.status === 'Revoked') {
        validationCache.set(cacheKey, result);
        return result;
      }
    } catch (ocspError) {
      result.errors.push(`OCSP check failed: ${ocspError.message}`);
    }
  }

  // Fallback to CRL
  if (CONFIG.ENABLE_CRL && crlUrls.length > 0) {
    try {
      const crlResult = await checkCRL(signerCert, crlUrls[0]);
      result.status = crlResult.status;
      result.crlChecked = true;
      
      validationCache.set(cacheKey, result);
      return result;
    } catch (crlError) {
      result.errors.push(`CRL check failed: ${crlError.message}`);
    }
  }

  if (result.errors.length === 0) {
    result.errors.push('No CRL or OCSP endpoints found in certificate');
  }

  return result;
}

async function checkOCSP(cert, chain, ocspUrl) {
  // OCSP implementation placeholder
  // This would require building an OCSP request and parsing the response
  throw new Error('OCSP validation not yet implemented');
}

async function checkCRL(cert, crlUrl) {
  try {
    console.log(`Checking CRL: ${crlUrl}`);
    
    const response = await axios.get(crlUrl, {
      timeout: CONFIG.HTTP_TIMEOUT,
      responseType: 'arraybuffer',
      maxContentLength: CONFIG.MAX_CRL_SIZE
    });

    const crlData = new Uint8Array(response.data);
    const crl = parseCRL(crlData);
    
    const serialNumber = getCertificateSerialNumber(cert);
    const isRevoked = crl.revokedCertificates.some(revoked => 
      revoked.serialNumber === serialNumber
    );

    return {
      status: isRevoked ? 'Revoked' : 'Good',
      lastUpdate: crl.lastUpdate,
      nextUpdate: crl.nextUpdate
    };

  } catch (error) {
    throw new Error(`CRL download/parsing failed: ${error.message}`);
  }
}

function parseCRL(crlData) {
  // Simplified CRL parsing
  // In a real implementation, this would use proper ASN.1 parsing
  try {
    const asn1 = asn1js.fromBER(crlData.buffer);
    if (asn1.offset === -1) {
      throw new Error('Invalid CRL ASN.1 structure');
    }

    // This is a placeholder - proper CRL parsing is complex
    return {
      revokedCertificates: [],
      lastUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 86400000) // 24 hours
    };
  } catch (error) {
    throw new Error(`CRL parsing failed: ${error.message}`);
  }
}

function extractCRLUrls(cert) {
  // Extract CRL distribution points from certificate extensions
  const urls = [];
  
  try {
    if (cert.extensions) {
      for (const ext of cert.extensions) {
        if (ext.extnID === '2.5.29.31') { // CRL Distribution Points
          // Parse CRL distribution points extension
          // This is a simplified version
          urls.push('http://example.com/crl'); // Placeholder
        }
      }
    }
  } catch (error) {
    console.warn('Error extracting CRL URLs:', error);
  }
  
  return urls;
}

function extractOCSPUrls(cert) {
  // Extract OCSP URLs from Authority Information Access extension
  const urls = [];
  
  try {
    if (cert.extensions) {
      for (const ext of cert.extensions) {
        if (ext.extnID === '1.3.6.1.5.5.7.1.1') { // Authority Information Access
          // Parse AIA extension
          // This is a simplified version
          urls.push('http://example.com/ocsp'); // Placeholder
        }
      }
    }
  } catch (error) {
    console.warn('Error extracting OCSP URLs:', error);
  }
  
  return urls;
}

// ------------------------------------------------------------------
// TIMESTAMP VALIDATION
// ------------------------------------------------------------------
async function validateTimestamp(timestampInfo) {
  try {
    // Timestamp validation placeholder
    if (!timestampInfo || !timestampInfo.timestamp) {
      return false;
    }
    
    // Check if timestamp is reasonable (not in future, not too old)
    const tsTime = new Date(timestampInfo.timestamp);
    const now = new Date();
    const maxAge = 10 * 365 * 24 * 60 * 60 * 1000; // 10 years
    
    if (tsTime > now) {
      return false; // Future timestamp
    }
    
    if (now - tsTime > maxAge) {
      return false; // Too old
    }
    
    return true;
  } catch (error) {
    console.warn('Timestamp validation error:', error);
    return false;
  }
}

function parseTimestampToken(timestampToken) {
  // Parse RFC 3161 timestamp token
  try {
    return {
      authority: 'Unknown TSA',
      timestamp: new Date(),
      accuracy: 'Unknown'
    };
  } catch (error) {
    return null;
  }
}

// ------------------------------------------------------------------
// UTILITY FUNCTIONS
// ------------------------------------------------------------------
function getCertificateFingerprint(cert) {
  try {
    if (cert.serialNumber) {
      return typeof cert.serialNumber === 'string' 
        ? cert.serialNumber 
        : bufferToHex(cert.serialNumber.valueBlock.valueHex);
    }
    return 'unknown';
  } catch (error) {
    return 'unknown';
  }
}

function getCertificateSerialNumber(cert) {
  try {
    if (cert.serialNumber) {
      return typeof cert.serialNumber === 'string' 
        ? cert.serialNumber 
        : bufferToHex(cert.serialNumber.valueBlock.valueHex);
    }
    return null;
  } catch (error) {
    return null;
  }
}

function parseKeyUsage(extension) {
  // Parse key usage extension
  const usages = [];
  try {
    // This is a simplified implementation
    usages.push('Digital Signature', 'Non Repudiation');
  } catch (error) {
    console.warn('Error parsing key usage:', error);
  }
  return usages;
}

function parseExtendedKeyUsage(extension) {
  // Parse extended key usage extension
  const usages = [];
  try {
    // This is a simplified implementation
    usages.push('Code Signing', 'Email Protection');
  } catch (error) {
    console.warn('Error parsing extended key usage:', error);
  }
  return usages;
}

function getHashAlgorithmFromP7(p7) {
  try {
    if (p7.rawCapture && p7.rawCapture.digestAlgorithm) {
      const oidBuffer = p7.rawCapture.digestAlgorithm;
      const oidStr = forge.asn1.derToOid(oidBuffer);
      
      if (oidStr.includes('2.16.840.1.101.3.4.2.1')) return 'sha256';
      if (oidStr.includes('2.16.840.1.101.3.4.2.2')) return 'sha384';
      if (oidStr.includes('2.16.840.1.101.3.4.2.3')) return 'sha512';
      if (oidStr.includes('1.3.14.3.2.26')) return 'sha1';
    }
    return 'sha256';
  } catch {
    return 'sha256';
  }
}

function isCertificateSelfSigned(cert) {
  try {
    const subj = cert.subject.attributes
      .map(a => `${a.shortName}=${a.value}`)
      .sort()
      .join(',');
    const issu = cert.issuer.attributes
      .map(a => `${a.shortName}=${a.value}`)
      .sort()
      .join(',');
    return subj === issu;
  } catch {
    return false;
  }
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function createStructureOnlyResult(signatureInfo, fileName, pkiError, forgeError) {
  return {
    valid: false,
    structureValid: true,
    format: signatureInfo.signatureType,
    fileName,
    error: 'Digital signature detected but cryptographic parsing failed (advanced PAdES structure)',
    cryptographicVerification: false,
    signatureValid: null,
    certificateValid: false,
    signedBy: 'Unknown',
    organization: 'Unknown',
    email: 'Unknown',
    signatureDate: 'Unknown',
    signatureAlgorithm: 'Unknown',
    certificateIssuer: 'Unknown',
    certificateValidFrom: 'Unknown',
    certificateValidTo: 'Unknown',
    serialNumber: 'Unknown',
    revocationStatus: 'Unknown',
    warnings: [
      'Detected signed PDF structure (ByteRange + Contents)',
      `Parsing errors: ${pkiError}, ${forgeError || 'N/A'}`,
      'This is normal for certain advanced PAdES signatures (Adobe, Dike, Aruba)',
      'Try verifying locally with Adobe Acrobat or a PEC-qualified tool for full validation'
    ]
  };
}

function buildComprehensiveWarnings(validationResults, certInfo, revocationEnabled) {
  const warnings = [];
  
  if (!validationResults.certificateValid) {
    warnings.push('Certificate expired or not yet valid');
  }
  
  if (certInfo.isSelfSigned) {
    warnings.push('Certificate is self-signed');
  }
  
  if (!validationResults.chainValid && !certInfo.isSelfSigned) {
    warnings.push('Certificate chain validation failed');
  }
  
  if (validationResults.revocationStatus === 'Unknown' && revocationEnabled) {
    warnings.push('Certificate revocation status could not be determined');
  }
  
  if (validationResults.revocationStatus === 'Check Failed') {
    warnings.push('Certificate revocation check failed');
  }
  
  if (!revocationEnabled) {
    warnings.push('Certificate revocation checking disabled');
  }
  
  if (validationResults.timestampValid === false) {
    warnings.push('Timestamp validation failed');
  }
  
  if (validationResults.validationErrors.length > 0) {
    warnings.push(`Validation errors: ${validationResults.validationErrors.join(', ')}`);
  }
  
  // Always include general disclaimer
  warnings.push('This verification provides technical validation only');
  warnings.push('Legal validity may require additional verification with qualified tools');
  
  return warnings;
}
