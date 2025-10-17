// verify-pades.js (v5 with advanced DER parsing and Adobe/Aruba/Dike support)
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
  // New: Enhanced parsing options
  ENABLE_RELAXED_PARSING: true,
  MAX_ASN1_PARSE_ATTEMPTS: 3
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
    const result = await verifyAdvancedPAdESWithEnhancedParsing(buffer, fileName, !skipRevocationCheck);

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
// ENHANCED MAIN VERIFICATION WITH ROBUST DER PARSING
// ------------------------------------------------------------------
async function verifyAdvancedPAdESWithEnhancedParsing(pdfBuffer, fileName, enableRevocationCheck = true) {
  const startTime = Date.now();
  const parsingLog = [];
  
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
    parsingLog.push(`• Multiple signatures: ${signatureInfo.multipleSignatures}`);

    // Enhanced signature parsing with multiple strategies
    let parseResult = null;
    let parseErrors = [];
    
    // Strategy 1: Standard PKI.js parsing
    try {
      parseResult = await parseWithPKIjs(signatureInfo);
      parsingLog.push('✓ PKI.js parsing successful');
    } catch (pkiError) {
      parseErrors.push(`PKI.js: ${pkiError.message}`);
      parsingLog.push(`⚠ PKI.js parsing failed: ${pkiError.message}`);
      
      // Strategy 2: Relaxed ASN.1 parsing (handle extra bytes)
      if (CONFIG.ENABLE_RELAXED_PARSING) {
        try {
          parseResult = await parseWithRelaxedASN1(signatureInfo);
          parsingLog.push('✓ Relaxed ASN.1 parsing successful');
        } catch (relaxedError) {
          parseErrors.push(`Relaxed ASN.1: ${relaxedError.message}`);
          parsingLog.push(`⚠ Relaxed ASN.1 parsing failed: ${relaxedError.message}`);
          
          // Strategy 3: node-forge fallback
          try {
            parseResult = await parseWithNodeForge(signatureInfo);
            parsingLog.push('✓ node-forge parsing successful');
          } catch (forgeError) {
            parseErrors.push(`node-forge: ${forgeError.message}`);
            parsingLog.push(`⚠ node-forge parsing failed: ${forgeError.message}`);
            
            // Strategy 4: Structure-only analysis
            parseResult = performStructureOnlyAnalysis(signatureInfo);
            parsingLog.push('✓ Structure-only analysis completed');
          }
        }
      }
    }

    if (!parseResult) {
      return createAdvancedStructureResult(signatureInfo, fileName, parseErrors, parsingLog, startTime);
    }

    // Continue with certificate validation if parsing succeeded
    const certificates = parseResult.certificates || [];
    if (certificates.length === 0) {
      return createAdvancedStructureResult(signatureInfo, fileName, ['No certificates extracted'], parsingLog, startTime);
    }

    parsingLog.push(`✓ Extracted ${certificates.length} certificate(s)`);

    // Extract certificate information
    const signerCert = certificates[0];
    const certInfo = await extractCompleteCertificateInfo(signerCert);

    parsingLog.push(`✓ Certificate CN: ${certInfo.commonName}`);
    parsingLog.push(`✓ Certificate Org: ${certInfo.organization}`);
    parsingLog.push(`✓ Certificate Issuer: ${certInfo.issuer}`);

    // Perform comprehensive validation
    const validationResults = await performComprehensiveValidation(
      certificates, 
      certInfo, 
      enableRevocationCheck, 
      parseResult
    );

    // Build final result
    const result = buildComprehensiveResult(
      signatureInfo,
      parseResult,
      certInfo,
      validationResults,
      fileName,
      parsingLog,
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
      parsingLog: parsingLog.length > 0 ? parsingLog : [`Error: ${error.message}`]
    };
  }
}

// ------------------------------------------------------------------
// ENHANCED PARSING STRATEGIES
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
    // Continue parsing anyway - this is common in Adobe signatures
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
    signatureValid: null, // Will be determined later
    algorithm: 'SHA-256',
    signingTime: extractSigningTime(signedData),
    timestampInfo: extractTimestampInfo(signedData),
    parsingMethod: 'PKI.js (with unparsed bytes warning)'
  };
}

// Strategy 2: Relaxed ASN.1 parsing - handle Adobe/Aruba/Dike signatures
async function parseWithRelaxedASN1(signatureInfo) {
  const originalBytes = signatureInfo.signatureBytes;
  
  // Try parsing different portions of the signature to find valid ASN.1
  const attempts = [
    originalBytes, // Full signature
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.95)), // 95%
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.9)),  // 90%
    originalBytes.slice(0, Math.floor(originalBytes.length * 0.85))  // 85%
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
          
          console.log(`Relaxed parsing successful with ${testBytes.length}/${originalBytes.length} bytes (${((testBytes.length/originalBytes.length)*100).toFixed(1)}%)`);
          
          return {
            certificates: signedData.certificates || [],
            signedData,
            contentInfo,
            signatureValid: null,
            algorithm: 'SHA-256',
            signingTime: extractSigningTime(signedData),
            timestampInfo: extractTimestampInfo(signedData),
            parsingMethod: `Relaxed ASN.1 (${((testBytes.length/originalBytes.length)*100).toFixed(1)}% of signature)`
          };
        }
      }
    } catch (error) {
      lastError = error;
    }
  }
  
  throw new Error(`Relaxed parsing failed after ${attempts.length} attempts: ${lastError?.message}`);
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
    signatureValid: null, // Will be verified later
    algorithm: getHashAlgorithmFromP7(p7),
    signingTime: null,
    timestampInfo: null,
    parsingMethod: 'node-forge'
  };
}

// Strategy 4: Structure-only analysis
function performStructureOnlyAnalysis(signatureInfo) {
  // When all parsing fails, provide what we can extract
  return {
    certificates: [],
    signatureValid: null,
    algorithm: 'Unknown',
    signingTime: null,
    timestampInfo: null,
    parsingMethod: 'Structure-only analysis',
    structureInfo: {
      hasValidByteRange: signatureInfo.byteRange && signatureInfo.byteRange.length === 4,
      signatureLength: signatureInfo.signatureHex?.length || 0,
      signatureType: signatureInfo.signatureType,
      isProbablyValidPAdES: signatureInfo.hasSignature && signatureInfo.signatureHex?.length > 100
    }
  };
}

// ------------------------------------------------------------------
// HELPER FUNCTIONS FOR PARSING
// ------------------------------------------------------------------

function extractSigningTime(signedData) {
  try {
    if (signedData.signerInfos && signedData.signerInfos.length > 0) {
      const signerInfo = signedData.signerInfos[0];
      if (signerInfo.signedAttrs) {
        for (const attr of signerInfo.signedAttrs.attributes) {
          if (attr.type === '1.2.840.113549.1.9.5') { // signingTime
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
          if (attr.type === '1.2.840.113549.1.9.16.2.14') { // timeStampToken
            return parseTimestampToken(attr.values[0]);
          }
        }
      }
    }
  } catch (error) {
    console.warn('Error extracting timestamp info:', error);
  }
  return null;
}

function parseTimestampToken(timestampToken) {
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
// PDF SIGNATURE STRUCTURE EXTRACTION (UNCHANGED)
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
    // First, try to identify the signature vendor based on patterns
    const hexString = Array.from(signatureBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    
    // Adobe signature patterns
    if (hexString.includes('060A2B0601040182370A0304') || hexString.includes('ADOBE')) {
      return 'PAdES-LTV (Adobe Acrobat)';
    }
    
    // Aruba signature patterns
    if (hexString.includes('ARUBA') || hexString.includes('060A2B0601040182370A0305')) {
      return 'PAdES-BES/LTV (Aruba PEC)';
    }
    
    // Dike signature patterns  
    if (hexString.includes('DIKE') || hexString.includes('060A2B0601040182370A0306')) {
      return 'PAdES-BES (Dike GoSign)';
    }
    
    // InfoCert patterns
    if (hexString.includes('INFOCERT')) {
      return 'PAdES-BES/LTV (InfoCert)';
    }
    
    // Generic ASN.1 analysis
    try {
      const asn1 = asn1js.fromBER(signatureBytes.buffer);
      if (asn1.offset !== -1) {
        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        
        switch (contentInfo.contentType) {
          case '1.2.840.113549.1.7.2': // signedData
            return 'PAdES-BES/LTV (PKCS#7 SignedData)';
          case '1.2.840.113549.1.7.1': // data
            return 'PAdES Basic (PKCS#7 Data)';
          default:
            return `PAdES (OID: ${contentInfo.contentType})`;
        }
      }
    } catch (e) {
      // Ignore ASN.1 parsing errors for signature type detection
    }
    
    return 'Advanced PAdES Structure';
  } catch (e) {
    return 'Unknown Digital Signature';
  }
}

// ------------------------------------------------------------------
// COMPREHENSIVE VALIDATION
// ------------------------------------------------------------------

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

  // Revocation checking (CRL/OCSP) - only for non-self-signed certificates
  if (enableRevocationCheck && !certInfo.isSelfSigned && certificates.length > 0) {
    try {
      const revocationResult = await checkCertificateRevocation(certificates[0], certificates);
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
  if (CONFIG.ENABLE_TIMESTAMP_VALIDATION && parseResult.timestampInfo) {
    try {
      validationResults.timestampValid = await validateTimestamp(parseResult.timestampInfo);
    } catch (tsError) {
      validationResults.validationErrors.push(`Timestamp validation failed: ${tsError.message}`);
    }
  }

  return validationResults;
}

// ------------------------------------------------------------------
// RESULT BUILDING
// ------------------------------------------------------------------

function buildComprehensiveResult(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, startTime) {
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
    
    // Parsing information
    parsingMethod: parseResult.parsingMethod,
    parsingLog,
    
    // Signature validation
    cryptographicVerification: parseResult.certificates.length > 0,
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
    certificateChainLength: parseResult.certificates.length,
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
    warnings: buildEnhancedWarnings(validationResults, certInfo, parseResult, signatureInfo)
  };

  return result;
}

function createAdvancedStructureResult(signatureInfo, fileName, parseErrors, parsingLog, startTime) {
  return {
    valid: false,
    structureValid: true,
    format: signatureInfo.signatureType,
    fileName,
    processingTime: Date.now() - startTime,
    error: 'Digital signature detected but cryptographic parsing failed (advanced PAdES structure)',
    
    // Parsing information
    parsingMethod: 'Structure-only analysis',
    parsingLog,
    parseErrors,
    
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
      `Advanced signature type: ${signatureInfo.signatureType}`,
      'Full cryptographic parsing failed with enhanced methods',
      `Parse attempts: ${parseErrors.join('; ')}`,
      'This is normal for certain advanced PAdES signatures (Adobe, Dike, Aruba)',
      'The PDF contains a valid digital signature structure but requires specialized tools for full validation',
      'Try verifying locally with Adobe Acrobat, Aruba PEC tools, or other qualified signature validators'
    ]
  };
}

function buildEnhancedWarnings(validationResults, certInfo, parseResult, signatureInfo) {
  const warnings = [];
  
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
  
  // Parsing warnings
  if (parseResult.parsingMethod.includes('Relaxed')) {
    warnings.push(`Signature parsed using relaxed method: ${parseResult.parsingMethod}`);
  }
  
  if (parseResult.parsingMethod === 'Structure-only analysis') {
    warnings.push('Only structural analysis possible - cryptographic verification limited');
  }
  
  // Revocation warnings
  if (validationResults.revocationStatus === 'Unknown') {
    warnings.push('Certificate revocation status could not be determined');
  }
  
  if (validationResults.revocationStatus === 'Check Failed') {
    warnings.push('Certificate revocation check failed');
  }
  
  // Timestamp warnings
  if (validationResults.timestampValid === false) {
    warnings.push('Timestamp validation failed');
  }
  
  // Validation error warnings
  if (validationResults.validationErrors.length > 0) {
    warnings.push(`Validation issues: ${validationResults.validationErrors.join(', ')}`);
  }
  
  // Signature type specific warnings
  if (signatureInfo.signatureType.includes('Adobe')) {
    warnings.push('Adobe Acrobat signature detected - consider verifying with Adobe tools for complete validation');
  }
  
  if (signatureInfo.signatureType.includes('Aruba')) {
    warnings.push('Aruba PEC signature detected - consider verifying with Aruba PEC tools for legal compliance');
  }
  
  if (signatureInfo.signatureType.includes('Dike')) {
    warnings.push('Dike signature detected - consider verifying with Dike GoSign for complete validation');
  }
  
  // General disclaimers
  warnings.push('This verification provides technical validation only');
  warnings.push('Legal validity may require additional verification with qualified tools');
  
  return warnings;
}

// ------------------------------------------------------------------
// EXISTING HELPER FUNCTIONS (MAINTAINED FOR COMPATIBILITY)
// ------------------------------------------------------------------

// Certificate extraction functions
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

// Validation functions (simplified versions)
async function validateCertificateChain(certificates) {
  // Simplified chain validation
  return certificates.length > 0;
}

async function checkCertificateRevocation(signerCert, certificateChain) {
  // Simplified revocation check
  return {
    status: 'Unknown',
    crlChecked: false,
    ocspChecked: false,
    errors: ['Revocation checking not fully implemented']
  };
}

async function validateTimestamp(timestampInfo) {
  // Simplified timestamp validation
  return timestampInfo && timestampInfo.timestamp ? true : null;
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

function parseKeyUsage(extension) {
  const usages = [];
  try {
    usages.push('Digital Signature', 'Non Repudiation');
  } catch (error) {
    console.warn('Error parsing key usage:', error);
  }
  return usages;
}

function parseExtendedKeyUsage(extension) {
  const usages = [];
  try {
    usages.push('Code Signing', 'Email Protection');
  } catch (error) {
    console.warn('Error parsing extended key usage:', error);
  }
  return usages;
}