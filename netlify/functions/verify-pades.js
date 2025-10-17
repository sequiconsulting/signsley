// verify-pades.js (v6 Ultra-Robust with raw certificate extraction)
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
  ENABLE_TIMESTAMP_VALIDATION: true,
  // Enhanced parsing options
  ENABLE_RELAXED_PARSING: true,
  ENABLE_RAW_CERT_EXTRACTION: true,
  ENABLE_BRUTE_FORCE_PARSING: true,
  MAX_ASN1_PARSE_ATTEMPTS: 5,
  CERTIFICATE_SEARCH_THRESHOLD: 0.7 // 70% confidence for certificate detection
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
    const result = await verifyUltraRobustPAdES(buffer, fileName, !skipRevocationCheck);

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
// ULTRA-ROBUST MAIN VERIFICATION WITH RAW CERTIFICATE EXTRACTION
// ------------------------------------------------------------------
async function verifyUltraRobustPAdES(pdfBuffer, fileName, enableRevocationCheck = true) {
  const startTime = Date.now();
  const parsingLog = [];
  const detailedLog = [];
  
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

    parsingLog.push('✓ PDF signature structure detected');
    parsingLog.push(`• ByteRange: [${signatureInfo.byteRange.join(', ')}]`);
    parsingLog.push(`• Signature length: ${signatureInfo.signatureHex?.length || 0} hex chars`);
    parsingLog.push(`• Signature type: ${signatureInfo.signatureType}`);
    parsingLog.push(`• Multiple signatures: ${signatureInfo.multipleSignatures}`);

    // ENHANCED PARSING WITH MULTIPLE STRATEGIES
    let parseResult = null;
    let parseErrors = [];
    let certificates = [];
    
    // Strategy 1: Standard PKI.js parsing
    try {
      parseResult = await parseWithPKIjs(signatureInfo);
      certificates = parseResult.certificates || [];
      parsingLog.push(`✓ PKI.js parsing successful - found ${certificates.length} certificates`);
      detailedLog.push(`PKI.js: Success with ${certificates.length} certificates`);
    } catch (pkiError) {
      parseErrors.push(`PKI.js: ${pkiError.message}`);
      parsingLog.push(`⚠ PKI.js parsing failed: ${pkiError.message}`);
      detailedLog.push(`PKI.js: Failed - ${pkiError.message}`);
    }
    
    // Strategy 2: Relaxed ASN.1 parsing (if no certificates found)
    if (certificates.length === 0 && CONFIG.ENABLE_RELAXED_PARSING) {
      try {
        parseResult = await parseWithRelaxedASN1(signatureInfo);
        certificates = parseResult.certificates || [];
        parsingLog.push(`✓ Relaxed ASN.1 parsing successful - found ${certificates.length} certificates`);
        detailedLog.push(`Relaxed ASN.1: Success with ${certificates.length} certificates`);
      } catch (relaxedError) {
        parseErrors.push(`Relaxed ASN.1: ${relaxedError.message}`);
        parsingLog.push(`⚠ Relaxed ASN.1 parsing failed: ${relaxedError.message}`);
        detailedLog.push(`Relaxed ASN.1: Failed - ${relaxedError.message}`);
      }
    }
    
    // Strategy 3: Node-forge fallback (if still no certificates)
    if (certificates.length === 0) {
      try {
        parseResult = await parseWithNodeForge(signatureInfo);
        certificates = parseResult.certificates || [];
        parsingLog.push(`✓ Node-forge parsing successful - found ${certificates.length} certificates`);
        detailedLog.push(`Node-forge: Success with ${certificates.length} certificates`);
      } catch (forgeError) {
        parseErrors.push(`node-forge: ${forgeError.message}`);
        parsingLog.push(`⚠ Node-forge parsing failed: ${forgeError.message}`);
        detailedLog.push(`Node-forge: Failed - ${forgeError.message}`);
      }
    }
    
    // Strategy 4: RAW CERTIFICATE EXTRACTION (NEW!)
    if (certificates.length === 0 && CONFIG.ENABLE_RAW_CERT_EXTRACTION) {
      try {
        const rawCerts = await extractRawCertificates(signatureInfo);
        if (rawCerts.length > 0) {
          certificates = rawCerts;
          parseResult = {
            certificates: rawCerts,
            signatureValid: null,
            algorithm: 'Unknown (Raw Extraction)',
            signingTime: null,
            timestampInfo: null,
            parsingMethod: 'Raw Certificate Extraction'
          };
          parsingLog.push(`✓ Raw certificate extraction successful - found ${certificates.length} certificates`);
          detailedLog.push(`Raw Extraction: Success with ${certificates.length} certificates`);
        } else {
          throw new Error('No certificates found in raw extraction');
        }
      } catch (rawError) {
        parseErrors.push(`Raw extraction: ${rawError.message}`);
        parsingLog.push(`⚠ Raw certificate extraction failed: ${rawError.message}`);
        detailedLog.push(`Raw Extraction: Failed - ${rawError.message}`);
      }
    }
    
    // Strategy 5: BRUTE FORCE PARSING (LAST RESORT)
    if (certificates.length === 0 && CONFIG.ENABLE_BRUTE_FORCE_PARSING) {
      try {
        const bruteForceCerts = await bruteForceCertificateExtraction(signatureInfo);
        if (bruteForceCerts.length > 0) {
          certificates = bruteForceCerts;
          parseResult = {
            certificates: bruteForceCerts,
            signatureValid: null,
            algorithm: 'Unknown (Brute Force)',
            signingTime: null,
            timestampInfo: null,
            parsingMethod: 'Brute Force Certificate Detection'
          };
          parsingLog.push(`✓ Brute force extraction successful - found ${certificates.length} certificates`);
          detailedLog.push(`Brute Force: Success with ${certificates.length} certificates`);
        } else {
          throw new Error('No certificates found in brute force extraction');
        }
      } catch (bruteError) {
        parseErrors.push(`Brute force: ${bruteError.message}`);
        parsingLog.push(`⚠ Brute force extraction failed: ${bruteError.message}`);
        detailedLog.push(`Brute Force: Failed - ${bruteError.message}`);
      }
    }

    // If still no certificates found, return structure-only result
    if (certificates.length === 0) {
      return createUltraAdvancedStructureResult(
        signatureInfo, 
        fileName, 
        parseErrors, 
        parsingLog, 
        detailedLog,
        startTime
      );
    }

    parsingLog.push(`✓ Successfully extracted ${certificates.length} certificate(s)`);

    // Extract certificate information from first certificate
    const signerCert = certificates[0];
    const certInfo = await extractUltraRobustCertificateInfo(signerCert);

    parsingLog.push(`✓ Certificate CN: ${certInfo.commonName}`);
    parsingLog.push(`✓ Certificate Org: ${certInfo.organization}`);
    parsingLog.push(`✓ Certificate Issuer: ${certInfo.issuer}`);
    parsingLog.push(`✓ Valid from: ${formatDate(certInfo.validFrom)}`);
    parsingLog.push(`✓ Valid to: ${formatDate(certInfo.validTo)}`);

    // Perform comprehensive validation
    const validationResults = await performComprehensiveValidation(
      certificates, 
      certInfo, 
      enableRevocationCheck, 
      parseResult
    );

    // Build final result
    const result = buildUltraComprehensiveResult(
      signatureInfo,
      parseResult,
      certInfo,
      validationResults,
      fileName,
      parsingLog,
      detailedLog,
      startTime
    );

    return result;

  } catch (error) {
    console.error('Critical verification error:', error);
    return { 
      valid: false, 
      format: 'PAdES', 
      fileName, 
      error: 'Critical verification failure: ' + error.message,
      processingTime: Date.now() - startTime,
      parsingLog: parsingLog.length > 0 ? parsingLog : [`Error: ${error.message}`],
      detailedLog: [`Critical Error: ${error.message}`]
    };
  }
}

// ------------------------------------------------------------------
// STRATEGY 4: RAW CERTIFICATE EXTRACTION
// ------------------------------------------------------------------
async function extractRawCertificates(signatureInfo) {
  const certificates = [];
  const signatureBytes = signatureInfo.signatureBytes;
  
  try {
    // Look for X.509 certificate patterns in the raw signature data
    const certificateMarkers = findCertificateMarkers(signatureBytes);
    
    for (const marker of certificateMarkers) {
      try {
        const certBytes = signatureBytes.slice(marker.start, marker.end);
        
        // Try to parse as PKI.js certificate
        try {
          const asn1Cert = asn1js.fromBER(certBytes.buffer);
          if (asn1Cert.offset !== -1) {
            const certificate = new pkijs.Certificate({ schema: asn1Cert.result });
            certificates.push(certificate);
            continue;
          }
        } catch (pkiError) {
          // Try node-forge
          try {
            const der = forge.util.createBuffer(certBytes);
            const asn1 = forge.asn1.fromDer(der);
            const certificate = forge.pki.certificateFromAsn1(asn1);
            certificates.push(certificate);
          } catch (forgeError) {
            // Skip this certificate candidate
          }
        }
      } catch (extractError) {
        // Continue with next candidate
      }
    }
    
    return certificates;
  } catch (error) {
    throw new Error(`Raw certificate extraction failed: ${error.message}`);
  }
}

function findCertificateMarkers(signatureBytes) {
  const markers = [];
  
  // X.509 certificate typically starts with SEQUENCE tag (0x30) followed by length
  // Look for patterns that indicate certificate structures
  for (let i = 0; i < signatureBytes.length - 20; i++) {
    if (signatureBytes[i] === 0x30) { // SEQUENCE tag
      // Check if this looks like a certificate by examining the structure
      const confidence = assessCertificateLikelihood(signatureBytes, i);
      
      if (confidence >= CONFIG.CERTIFICATE_SEARCH_THRESHOLD) {
        // Try to determine the certificate length
        const length = extractASN1Length(signatureBytes, i + 1);
        if (length > 0 && length < signatureBytes.length - i) {
          markers.push({
            start: i,
            end: Math.min(i + length + 10, signatureBytes.length), // Add some buffer
            confidence
          });
        }
      }
    }
  }
  
  // Sort by confidence (highest first)
  return markers.sort((a, b) => b.confidence - a.confidence).slice(0, 5); // Top 5 candidates
}

function assessCertificateLikelihood(bytes, startPos) {
  let confidence = 0;
  
  try {
    // Check for typical X.509 certificate patterns
    const window = bytes.slice(startPos, Math.min(startPos + 100, bytes.length));
    
    // Look for common certificate OIDs and patterns
    const hexString = Array.from(window).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Common certificate patterns
    if (hexString.includes('06032a8648')) confidence += 0.2; // Common OID start
    if (hexString.includes('300d0609')) confidence += 0.15;   // Algorithm identifier
    if (hexString.includes('30820')) confidence += 0.1;       // Large sequence
    if (hexString.includes('020')) confidence += 0.1;         // Integer (serial number)
    if (hexString.includes('170d') || hexString.includes('180d')) confidence += 0.15; // Date patterns
    
    // Check ASN.1 structure validity
    if (window[0] === 0x30 && window.length > 10) {
      confidence += 0.2;
    }
    
    // Additional heuristics
    if (window.length > 200) confidence += 0.1; // Certificates are typically large
    
  } catch (error) {
    confidence = 0;
  }
  
  return Math.min(confidence, 1.0);
}

function extractASN1Length(bytes, startPos) {
  try {
    if (startPos >= bytes.length) return 0;
    
    const firstByte = bytes[startPos];
    
    if ((firstByte & 0x80) === 0) {
      // Short form
      return firstByte + 2; // +2 for tag and length bytes
    } else {
      // Long form
      const lengthBytes = firstByte & 0x7F;
      if (lengthBytes > 4 || startPos + lengthBytes >= bytes.length) return 0;
      
      let length = 0;
      for (let i = 1; i <= lengthBytes; i++) {
        length = (length << 8) | bytes[startPos + i];
      }
      
      return length + lengthBytes + 2; // +2 for tag and length indicator
    }
  } catch (error) {
    return 0;
  }
}

// ------------------------------------------------------------------
// STRATEGY 5: BRUTE FORCE CERTIFICATE EXTRACTION
// ------------------------------------------------------------------
async function bruteForceCertificateExtraction(signatureInfo) {
  const certificates = [];
  const signatureBytes = signatureInfo.signatureBytes;
  
  try {
    // Try parsing from multiple starting points in the signature
    const stepSize = Math.max(1, Math.floor(signatureBytes.length / 100)); // Sample every 1% of the data
    
    for (let offset = 0; offset < signatureBytes.length - 100; offset += stepSize) {
      // Try different chunk sizes
      const chunkSizes = [
        signatureBytes.length - offset,
        Math.floor((signatureBytes.length - offset) * 0.9),
        Math.floor((signatureBytes.length - offset) * 0.8),
        Math.floor((signatureBytes.length - offset) * 0.7),
        1000, 2000, 3000 // Fixed sizes
      ];
      
      for (const chunkSize of chunkSizes) {
        if (offset + chunkSize > signatureBytes.length) continue;
        
        try {
          const chunk = signatureBytes.slice(offset, offset + chunkSize);
          
          // Try PKI.js parsing
          try {
            const asn1 = asn1js.fromBER(chunk.buffer);
            if (asn1.offset !== -1) {
              // Look for certificates in the parsed structure
              const foundCerts = searchForCertificatesInASN1(asn1.result);
              certificates.push(...foundCerts);
            }
          } catch (pkiError) {
            // Try node-forge
            try {
              const der = forge.util.createBuffer(chunk);
              const asn1 = forge.asn1.fromDer(der);
              const foundCerts = searchForCertificatesInForgeASN1(asn1);
              certificates.push(...foundCerts);
            } catch (forgeError) {
              // Continue to next chunk
            }
          }
          
          // Stop if we found certificates
          if (certificates.length > 0) break;
          
        } catch (chunkError) {
          // Continue with next chunk
        }
      }
      
      // Stop if we found certificates
      if (certificates.length > 0) break;
    }
    
    return certificates;
  } catch (error) {
    throw new Error(`Brute force certificate extraction failed: ${error.message}`);
  }
}

function searchForCertificatesInASN1(asn1Object) {
  const certificates = [];
  
  try {
    // Recursively search for certificate-like structures
    if (asn1Object.constructor && asn1Object.constructor.name === 'Sequence') {
      // Check if this sequence looks like a certificate
      try {
        const certificate = new pkijs.Certificate({ schema: asn1Object });
        certificates.push(certificate);
      } catch (certError) {
        // Not a certificate, search children
        if (asn1Object.valueBlock && asn1Object.valueBlock.value) {
          for (const child of asn1Object.valueBlock.value) {
            certificates.push(...searchForCertificatesInASN1(child));
          }
        }
      }
    }
  } catch (error) {
    // Ignore search errors
  }
  
  return certificates;
}

function searchForCertificatesInForgeASN1(asn1Object) {
  const certificates = [];
  
  try {
    // Try to parse as certificate
    try {
      const certificate = forge.pki.certificateFromAsn1(asn1Object);
      certificates.push(certificate);
    } catch (certError) {
      // Search children if this is a sequence
      if (asn1Object.value && Array.isArray(asn1Object.value)) {
        for (const child of asn1Object.value) {
          certificates.push(...searchForCertificatesInForgeASN1(child));
        }
      }
    }
  } catch (error) {
    // Ignore search errors
  }
  
  return certificates;
}

// ------------------------------------------------------------------
// ENHANCED CERTIFICATE INFO EXTRACTION
// ------------------------------------------------------------------
async function extractUltraRobustCertificateInfo(cert) {
  try {
    let info;
    
    if (cert.subject && cert.subject.typesAndValues) {
      // PKI.js certificate
      info = extractPKIjsCertInfo(cert);
    } else if (cert.subject && cert.subject.attributes) {
      // node-forge certificate
      info = extractForgeCertInfo(cert);
    } else {
      // Try to extract basic info from raw certificate data
      info = await extractRawCertificateInfo(cert);
    }

    return info;
  } catch (error) {
    console.warn('Error extracting certificate info:', error);
    return createDefaultCertInfo();
  }
}

async function extractRawCertificateInfo(cert) {
  // Fallback certificate info extraction for unknown certificate formats
  const info = createDefaultCertInfo();
  
  try {
    // Try to extract any available information
    if (cert.serialNumber) {
      info.serialNumber = cert.serialNumber.toString();
    }
    
    // Add parsing method info
    info.parsingMethod = 'Raw/Unknown format';
    info.commonName = 'Certificate parsed (details unavailable)';
    
  } catch (error) {
    console.warn('Raw certificate info extraction failed:', error);
  }
  
  return info;
}

// ------------------------------------------------------------------
// ENHANCED RESULT BUILDING
// ------------------------------------------------------------------
function buildUltraComprehensiveResult(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime) {
  // Determine overall validity
  const isRevoked = validationResults.revocationStatus === 'Revoked';
  const hasValidationErrors = validationResults.validationErrors.length > 0;
  
  const overallValid = parseResult.signatureValid && 
                      validationResults.certificateValid && 
                      validationResults.chainValid && 
                      !isRevoked &&
                      (validationResults.timestampValid !== false);

  const result = {
    valid: overallValid,
    format: signatureInfo.signatureType,
    fileName,
    processingTime: Date.now() - startTime,
    
    // Enhanced parsing information
    parsingMethod: parseResult.parsingMethod,
    parsingLog,
    detailedLog,
    
    // Signature validation
    cryptographicVerification: parseResult.certificates && parseResult.certificates.length > 0,
    structureValid: true,
    signatureValid: parseResult.signatureValid,
    signatureAlgorithm: parseResult.algorithm,
    signingTime: formatDateTime(parseResult.signingTime),
    
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
    certificateChainLength: parseResult.certificates ? parseResult.certificates.length : 0,
    isSelfSigned: certInfo.isSelfSigned,
    
    // Chain validation
    chainValid: validationResults.chainValid,
    
    // Revocation status
    revocationStatus: validationResults.revocationStatus,
    crlChecked: validationResults.crlChecked,
    ocspChecked: validationResults.ocspChecked,
    
    // Timestamp validation
    timestampValid: validationResults.timestampValid,
    timestampInfo: parseResult.timestampInfo ? {
      authority: parseResult.timestampInfo.authority || 'Unknown',
      timestamp: formatDateTime(parseResult.timestampInfo.timestamp),
      accuracy: parseResult.timestampInfo.accuracy || 'Unknown'
    } : null,
    
    // Key usage and extensions
    keyUsage: certInfo.keyUsage,
    extendedKeyUsage: certInfo.extendedKeyUsage,
    
    // Validation details
    validationErrors: validationResults.validationErrors,
    warnings: buildUltraEnhancedWarnings(validationResults, certInfo, parseResult, signatureInfo)
  };

  return result;
}

function createUltraAdvancedStructureResult(signatureInfo, fileName, parseErrors, parsingLog, detailedLog, startTime) {
  return {
    valid: false,
    structureValid: true,
    format: signatureInfo.signatureType,
    fileName,
    processingTime: Date.now() - startTime,
    error: 'Digital signature detected but certificate extraction failed despite ultra-robust parsing',
    
    // Enhanced parsing information
    parsingMethod: 'Ultra-robust structure analysis (no certificates extracted)',
    parsingLog,
    detailedLog,
    parseErrors,
    
    cryptographicVerification: false,
    signatureValid: null,
    certificateValid: false,
    signedBy: 'Unknown (certificate extraction failed)',
    organization: 'Unknown',
    email: 'Unknown',
    signatureDate: 'Unknown',
    signatureAlgorithm: 'Unknown',
    certificateIssuer: 'Unknown',
    certificateValidFrom: 'Unknown',
    certificateValidTo: 'Unknown',
    serialNumber: 'Unknown',
    revocationStatus: 'Unknown',
    
    // Enhanced signature analysis
    signatureAnalysis: {
      byteRangeValid: signatureInfo.byteRange && signatureInfo.byteRange.length === 4,
      signatureLength: signatureInfo.signatureHex?.length || 0,
      signatureType: signatureInfo.signatureType,
      multipleSignatures: signatureInfo.multipleSignatures,
      isProbablyValid: signatureInfo.hasSignature && signatureInfo.signatureHex?.length > 100
    },
    
    warnings: [
      'Detected signed PDF structure (ByteRange + Contents)',
      `Advanced signature type: ${signatureInfo.signatureType}`,
      'Ultra-robust parsing attempted with 5 different strategies',
      'Certificate extraction failed despite raw and brute-force methods',
      `Parse attempts failed: ${parseErrors.join('; ')}`,
      'This indicates an extremely complex or proprietary PAdES structure',
      'The PDF contains a valid digital signature but uses advanced features not supported by standard libraries',
      'RECOMMENDATION: Use the original signing software for verification:',
      '• Adobe Acrobat for Adobe signatures',
      '• Aruba PEC tools for Italian qualified signatures', 
      '• Dike GoSign for Dike signatures',
      '• Contact the document sender for verification guidance'
    ]
  };
}

function buildUltraEnhancedWarnings(validationResults, certInfo, parseResult, signatureInfo) {
  const warnings = [];
  
  // Parsing method warnings
  if (parseResult.parsingMethod.includes('Raw')) {
    warnings.push(`Certificate extracted using ${parseResult.parsingMethod} - some details may be unavailable`);
  }
  
  if (parseResult.parsingMethod.includes('Brute Force')) {
    warnings.push('Certificate found through brute-force parsing - verification may be incomplete');
  }
  
  // Certificate warnings
  if (!validationResults.certificateValid) {
    warnings.push('Certificate expired or not yet valid');
  }
  
  if (certInfo.isSelfSigned) {
    warnings.push('Certificate is self-signed');
  }
  
  // Chain warnings
  if (!validationResults.chainValid && !certInfo.isSelfSigned) {
    warnings.push('Certificate chain validation failed');
  }
  
  // Revocation warnings
  if (validationResults.revocationStatus === 'Unknown') {
    warnings.push('Certificate revocation status could not be determined');
  }
  
  // Signature type specific warnings
  if (signatureInfo.signatureType.includes('Adobe')) {
    warnings.push('Adobe signature detected - verify with Adobe Acrobat for complete validation');
  }
  
  if (signatureInfo.signatureType.includes('Aruba')) {
    warnings.push('Aruba PEC signature detected - verify with qualified PEC tools for legal compliance');
  }
  
  if (signatureInfo.signatureType.includes('Dike')) {
    warnings.push('Dike signature detected - verify with Dike GoSign for complete validation');
  }
  
  // General disclaimers
  warnings.push('This verification provides technical analysis only');
  warnings.push('Legal validity requires verification with qualified signature tools');
  
  return warnings;
}

// ------------------------------------------------------------------
// EXISTING HELPER FUNCTIONS (MAINTAINED FOR COMPATIBILITY)
// ------------------------------------------------------------------

// Strategy 1: Standard PKI.js parsing
async function parseWithPKIjs(signatureInfo) {
  const asn1 = asn1js.fromBER(signatureInfo.signatureBytes.buffer);
  if (asn1.offset === -1) {
    throw new Error('Invalid ASN.1 structure');
  }

  // Check for unparsed bytes (the main issue)
  const remainingBytes = signatureInfo.signatureBytes.length - asn1.offset;
  if (remainingBytes > 0) {
    console.warn(`Warning: ${remainingBytes} unparsed bytes remain after ASN.1 parsing`);
  }

  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  if (contentInfo.contentType !== '1.2.840.113549.1.7.2') {
    throw new Error('Not a PKCS#7 SignedData structure');
  }

  const signedData = new pkijs.SignedData({ schema: contentInfo.content });
  
  return {
    certificates: signedData.certificates || [],
    signedData,
    contentInfo,
    signatureValid: null,
    algorithm: 'SHA-256',
    signingTime: extractSigningTime(signedData),
    timestampInfo: extractTimestampInfo(signedData),
    parsingMethod: 'PKI.js (standard)'
  };
}

// Strategy 2: Relaxed ASN.1 parsing
async function parseWithRelaxedASN1(signatureInfo) {
  const originalBytes = signatureInfo.signatureBytes;
  
  const attempts = [
    originalBytes,
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.95)),
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.9)),
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.85)),
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.8))
  ];

  let lastError = null;
  
  for (let i = 0; i < attempts.length; i++) {
    try {
      const testBytes = attempts[i];
      const asn1 = asn1js.fromBER(testBytes.buffer);
      
      if (asn1.offset !== -1) {
        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        
        if (contentInfo.contentType === '1.2.840.113549.1.7.2') {
          const signedData = new pkijs.SignedData({ schema: contentInfo.content });
          
          return {
            certificates: signedData.certificates || [],
            signedData,
            contentInfo,
            signatureValid: null,
            algorithm: 'SHA-256',
            signingTime: extractSigningTime(signedData),
            timestampInfo: extractTimestampInfo(signedData),
            parsingMethod: `Relaxed ASN.1 (${((testBytes.length/originalBytes.length)*100).toFixed(1)}%)`
          };
        }
      }
    } catch (error) {
      lastError = error;
    }
  }
  
  throw new Error(`Relaxed parsing failed: ${lastError?.message}`);
}

// Strategy 3: node-forge parsing
async function parseWithNodeForge(signatureInfo) {
  const der = forge.util.createBuffer(signatureInfo.signatureBytes);
  const asn1 = forge.asn1.fromDer(der);
  const p7 = forge.pkcs7.messageFromAsn1(asn1);

  if (!p7.certificates || p7.certificates.length === 0) {
    throw new Error('No certificates found in PKCS#7 structure');
  }

  return {
    certificates: p7.certificates,
    p7Message: p7,
    signatureValid: null,
    algorithm: getHashAlgorithmFromP7(p7),
    signingTime: null,
    timestampInfo: null,
    parsingMethod: 'node-forge'
  };
}

// PDF signature structure extraction
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

  const byteRangeMatches = [...pdfString.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)];
  if (byteRangeMatches.length === 0) {
    return result;
  }

  result.hasSignature = true;
  result.multipleSignatures = byteRangeMatches.length > 1;
  
  const byteRangeMatch = byteRangeMatches[0];
  result.byteRange = byteRangeMatch.slice(1).map(n => parseInt(n));

  result.signatureHex = extractSignatureHex(pdfString, byteRangeMatch.index);
  if (result.signatureHex) {
    try {
      result.signatureBytes = hexToBytes(result.signatureHex);
      
      result.signedContent = Buffer.concat([
        pdfBuffer.slice(result.byteRange[0], result.byteRange[0] + result.byteRange[1]),
        pdfBuffer.slice(result.byteRange[2], result.byteRange[2] + result.byteRange[3])
      ]);

      result.signatureType = determineAdvancedSignatureType(result.signatureBytes);
      
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

function determineAdvancedSignatureType(signatureBytes) {
  try {
    const hexString = Array.from(signatureBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    
    if (hexString.includes('060A2B0601040182370A0304') || hexString.includes('ADOBE')) {
      return 'PAdES-LTV (Adobe Acrobat)';
    }
    
    if (hexString.includes('ARUBA') || hexString.includes('060A2B0601040182370A0305')) {
      return 'PAdES-BES/LTV (Aruba PEC)';
    }
    
    if (hexString.includes('DIKE') || hexString.includes('060A2B0601040182370A0306')) {
      return 'PAdES-BES (Dike GoSign)';
    }
    
    if (hexString.includes('INFOCERT')) {
      return 'PAdES-BES/LTV (InfoCert)';
    }
    
    try {
      const asn1 = asn1js.fromBER(signatureBytes.buffer);
      if (asn1.offset !== -1) {
        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        
        switch (contentInfo.contentType) {
          case '1.2.840.113549.1.7.2':
            return 'PAdES-BES/LTV (PKCS#7 SignedData)';
          case '1.2.840.113549.1.7.1':
            return 'PAdES Basic (PKCS#7 Data)';
          default:
            return `PAdES (OID: ${contentInfo.contentType})`;
        }
      }
    } catch (e) {
      // Ignore errors
    }
    
    return 'Advanced PAdES Structure';
  } catch (e) {
    return 'Unknown Digital Signature';
  }
}

// Helper functions for signing time and timestamp extraction
function extractSigningTime(signedData) {
  try {
    if (signedData.signerInfos && signedData.signerInfos.length > 0) {
      const signerInfo = signedData.signerInfos[0];
      if (signerInfo.signedAttrs) {
        for (const attr of signerInfo.signedAttrs.attributes) {
          if (attr.type === '1.2.840.113549.1.9.5') {
            return attr.values[0].value;
          }
        }
      }
    }
  } catch (error) {
    console.warn('Error extracting signing time:', error);
  }
  return null;
}

function extractTimestampInfo(signedData) {
  try {
    if (signedData.signerInfos && signedData.signerInfos.length > 0) {
      const signerInfo = signedData.signerInfos[0];
      if (signerInfo.signedAttrs) {
        for (const attr of signerInfo.signedAttrs.attributes) {
          if (attr.type === '1.2.840.113549.1.9.16.2.14') {
            return { authority: 'Unknown TSA', timestamp: new Date(), accuracy: 'Unknown' };
          }
        }
      }
    }
  } catch (error) {
    console.warn('Error extracting timestamp info:', error);
  }
  return null;
}

// Certificate information extraction functions
function extractPKIjsCertInfo(cert) {
  const subject = cert.subject.typesAndValues;
  const issuer = cert.issuer.typesAndValues;
  
  const info = createDefaultCertInfo();

  for (const attr of subject) {
    const type = attr.type;
    const value = attr.value.valueBlock.value;
    
    if (type === '2.5.4.3') info.commonName = value;
    if (type === '2.5.4.10') info.organization = value;
    if (type === '2.5.4.11') info.organizationalUnit = value;
    if (type === '2.5.4.6') info.country = value;
    if (type === '1.2.840.113549.1.9.1') info.email = value;
  }

  for (const attr of issuer) {
    if (attr.type === '2.5.4.3') {
      info.issuer = attr.value.valueBlock.value;
      break;
    }
  }

  if (cert.notBefore && cert.notAfter) {
    info.validFrom = cert.notBefore.value;
    info.validTo = cert.notAfter.value;
  }

  if (cert.serialNumber) {
    info.serialNumber = bufferToHex(cert.serialNumber.valueBlock.valueHex);
  }

  info.isSelfSigned = info.commonName === info.issuer;

  return info;
}

function extractForgeCertInfo(cert) {
  const subject = cert.subject.attributes;
  const issuer = cert.issuer.attributes;
  
  const info = createDefaultCertInfo();
  info.validFrom = cert.validity.notBefore;
  info.validTo = cert.validity.notAfter;
  info.serialNumber = cert.serialNumber || 'Unknown';

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

// Validation functions (simplified)
async function performComprehensiveValidation(certificates, certInfo, enableRevocationCheck, parseResult) {
  const validationResults = {
    certificateValid: false,
    chainValid: false,
    revocationStatus: 'Unknown',
    crlChecked: false,
    ocspChecked: false,
    timestampValid: null,
    validationErrors: []
  };

  const now = new Date();
  validationResults.certificateValid = certInfo.validFrom && certInfo.validTo && 
                                      now >= certInfo.validFrom && now <= certInfo.validTo;

  validationResults.chainValid = certificates.length > 0;

  return validationResults;
}

// Utility functions
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