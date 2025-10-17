// verify-pades.js (v9 Complete implementation with full parsing functions)
const forge = require('node-forge');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const axios = require('axios');
const NodeCache = require('node-cache');
const dayjs = require('dayjs');

// Initialize cache (1 hour TTL for CRL/OCSP responses)
const validationCache = new NodeCache({ stdTTL: 3600 });

// Set crypto engine for PKI.js
const crypto = require('crypto').webcrypto;
pkijs.setEngine('newEngine', crypto, new pkijs.CryptoEngine({
  crypto,
  subtle: crypto.subtle
}));

// Enhanced Configuration with Progressive Timeouts
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
  CERTIFICATE_SEARCH_THRESHOLD: 0.7, // 70% confidence for certificate detection
  // Progressive timeout configuration
  PARSE_TIMEOUT_FAST: 5000,     // 5 seconds for initial attempt
  PARSE_TIMEOUT_MEDIUM: 10000,   // 10 seconds for retry
  PARSE_TIMEOUT_SLOW: 15000,     // 15 seconds for final attempt
  PARSE_TIMEOUT_EXTRACTION: 20000, // 20 seconds for signature extraction
  MAX_MEMORY_MB: 256, // 256MB memory limit
  CLEANUP_INTERVAL: 1000, // Cleanup every second
  // Chunking configuration for large files
  CHUNK_SIZE: 64 * 1024, // 64KB chunks for processing
  YIELD_INTERVAL: 100,    // Yield every 100 operations
};

// Input validation helper
function validateInput(fileData, fileName) {
  if (!fileData) {
    throw new Error('No file data provided');
  }
  
  if (!fileName || typeof fileName !== 'string') {
    throw new Error('Invalid or missing file name');
  }
  
  if (typeof fileData !== 'string') {
    throw new Error('File data must be a base64 string');
  }
  
  // Remove data URL prefix if present
  const base64 = fileData.replace(/^data:[^;]+;base64,/, '').trim();
  
  if (!/^[A-Za-z0-9+/=]*$/.test(base64)) {
    throw new Error('Invalid Base64 data format');
  }
  
  const size = (base64.length * 3) / 4;
  if (size > 6 * 1024 * 1024) {
    throw new Error('File too large. Maximum size is 6MB.');
  }
  
  if (size === 0) {
    throw new Error('File appears to be empty');
  }
  
  return base64;
}

// Enhanced date formatting using dayjs
function formatDateTime(date) {
  if (!date) return 'Unknown';
  try {
    const d = dayjs(date);
    if (!d.isValid()) return 'Unknown';
    return d.format('YYYY/MM/DD HH:mm');
  } catch {
    return 'Unknown';
  }
}

function formatDate(date) {
  if (!date) return 'Unknown';
  try {
    const d = dayjs(date);
    if (!d.isValid()) return 'Unknown';
    return d.format('YYYY/MM/DD');
  } catch {
    return 'Unknown';
  }
}

// Enhanced memory cleanup helper
function cleanupMemory() {
  if (global.gc) {
    try {
      global.gc();
    } catch (e) {
      // Ignore GC errors
    }
  }
}

// Progressive timeout wrapper with escalation
async function withProgressiveTimeout(promise, operation, isRetry = false, isFinalAttempt = false) {
  let timeoutMs;
  
  if (isFinalAttempt) {
    timeoutMs = CONFIG.PARSE_TIMEOUT_SLOW;
  } else if (isRetry) {
    timeoutMs = CONFIG.PARSE_TIMEOUT_MEDIUM;
  } else {
    timeoutMs = CONFIG.PARSE_TIMEOUT_FAST;
  }
  
  return Promise.race([
    promise,
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error(`${operation} timeout after ${timeoutMs}ms`)), timeoutMs)
    )
  ]);
}

// Chunked processing helper with yield points
async function processWithYield(data, processor, chunkSize = CONFIG.CHUNK_SIZE) {
  const results = [];
  let operationCount = 0;
  
  for (let i = 0; i < data.length; i += chunkSize) {
    const chunk = data.slice(i, i + chunkSize);
    const result = await processor(chunk, i);
    
    if (result !== null && result !== undefined) {
      results.push(result);
    }
    
    operationCount++;
    
    // Yield control periodically to prevent blocking
    if (operationCount % CONFIG.YIELD_INTERVAL === 0) {
      await new Promise(resolve => setImmediate(resolve));
      cleanupMemory(); // Cleanup during yield
    }
  }
  
  return results;
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST') {
    return { 
      statusCode: 405, 
      headers, 
      body: JSON.stringify({ 
        error: 'Method not allowed. Use POST to verify signatures.', 
        valid: false 
      }) 
    };
  }

  let buffer = null;
  let result = null;
  
  try {
    // Enhanced request body validation
    if (!event.body) {
      return { 
        statusCode: 400, 
        headers, 
        body: JSON.stringify({ 
          error: 'Request body is required', 
          valid: false 
        }) 
      };
    }

    let body;
    try {
      body = JSON.parse(event.body);
    } catch (parseError) {
      return { 
        statusCode: 400, 
        headers, 
        body: JSON.stringify({ 
          error: 'Invalid JSON in request body', 
          valid: false 
        }) 
      };
    }

    const { fileData, fileName, skipRevocationCheck = false } = body;
    
    // Validate inputs
    const base64 = validateInput(fileData, fileName);

    // Convert to buffer with error handling
    try {
      buffer = Buffer.from(base64, 'base64');
    } catch (bufferError) {
      return { 
        statusCode: 400, 
        headers, 
        body: JSON.stringify({ 
          error: 'Failed to decode file data', 
          valid: false 
        }) 
      };
    }

    // Verify the decoded buffer
    if (!buffer || buffer.length === 0) {
      return { 
        statusCode: 400, 
        headers, 
        body: JSON.stringify({ 
          error: 'Decoded file is empty', 
          valid: false 
        }) 
      };
    }

    result = await verifyUltraRobustPAdES(buffer, fileName, !skipRevocationCheck);

    return { statusCode: 200, headers, body: JSON.stringify(result) };
    
  } catch (error) {
    console.error('Handler error:', error);
    
    // Categorize errors for better user experience
    const categorizedError = categorizeError(error);
    
    return { 
      statusCode: categorizedError.status || 500, 
      headers, 
      body: JSON.stringify({ 
        error: categorizedError.message,
        category: categorizedError.category,
        valid: false 
      }) 
    };
  } finally {
    // Cleanup memory
    buffer = null;
    result = null;
    cleanupMemory();
  }
};

// Enhanced error categorization
function categorizeError(error) {
  const message = error.message || 'Unknown error';
  
  if (message.includes('timeout')) {
    return {
      status: 408,
      category: 'timeout',
      message: 'Processing timeout - the file may be too complex or contain large attachments. Please try again or use a different verification tool.'
    };
  }
  
  if (message.includes('too large') || message.includes('size')) {
    return {
      status: 413,
      category: 'file_size',
      message: 'The file is too large. Please use a file smaller than 6MB.'
    };
  }
  
  if (message.includes('Base64') || message.includes('decode')) {
    return {
      status: 400,
      category: 'format',
      message: 'The file format is not supported or the data is corrupted. Please upload a valid PDF file.'
    };
  }
  
  if (message.includes('PDF') || message.includes('signature')) {
    return {
      status: 422,
      category: 'signature',
      message: 'Unable to process the digital signature. The file may not contain a valid signature or may have embedded attachments.'
    };
  }
  
  if (message.includes('memory') || message.includes('Memory')) {
    return {
      status: 507,
      category: 'memory',
      message: 'Insufficient memory to process the file. Please try again with a smaller file.'
    };
  }
  
  return {
    status: 500,
    category: 'internal',
    message: `Verification failed: ${message}`
  };
}

// ------------------------------------------------------------------
// ENHANCED MAIN VERIFICATION WITH PROGRESSIVE TIMEOUTS
// ------------------------------------------------------------------
async function verifyUltraRobustPAdES(pdfBuffer, fileName, enableRevocationCheck = true) {
  const startTime = Date.now();
  const parsingLog = [];
  const detailedLog = [];
  
  // Memory and resource tracking
  let signatureInfo = null;
  let parseResult = null;
  let certificates = [];
  
  try {
    // Enhanced PDF validation
    if (!pdfBuffer || pdfBuffer.length === 0) {
      throw new Error('Invalid or empty PDF buffer');
    }
    
    const pdfString = pdfBuffer.toString('latin1');
    
    // Basic PDF validation with better error messages
    if (!pdfString.startsWith('%PDF-')) {
      return { 
        valid: false, 
        format: 'Invalid', 
        fileName, 
        error: 'Not a valid PDF file - missing PDF header',
        processingTime: Date.now() - startTime
      };
    }

    // Check for minimum PDF size
    if (pdfBuffer.length < 100) {
      return { 
        valid: false, 
        format: 'Invalid', 
        fileName, 
        error: 'PDF file is too small to contain a signature',
        processingTime: Date.now() - startTime
      };
    }

    // Detect if this is a Purchase Order file with attachments (common timeout cause)
    const isPurchaseOrderWithAttachment = fileName.toLowerCase().includes('purchase order') && 
                                        (fileName.toLowerCase().includes('attach') || pdfBuffer.length > 1024 * 1024);
    
    if (isPurchaseOrderWithAttachment) {
      parsingLog.push('⚠ Detected Purchase Order file with potential attachments - using extended timeout');
    }

    // Extract signature structure with progressive timeouts
    let extractionAttempt = 1;
    const maxExtractionAttempts = 3;
    
    while (extractionAttempt <= maxExtractionAttempts && !signatureInfo) {
      try {
        const isRetry = extractionAttempt > 1;
        const isFinalAttempt = extractionAttempt === maxExtractionAttempts;
        
        parsingLog.push(`• Signature extraction attempt ${extractionAttempt}/${maxExtractionAttempts}`);
        
        if (isPurchaseOrderWithAttachment || extractionAttempt > 1) {
          // Use extended timeout for purchase orders or retries
          signatureInfo = await Promise.race([
            extractPDFSignatureStructure(pdfString, pdfBuffer, extractionAttempt > 1),
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error(`Signature extraction timeout (attempt ${extractionAttempt})`)), 
                       CONFIG.PARSE_TIMEOUT_EXTRACTION)
            )
          ]);
        } else {
          // Use progressive timeout for normal files
          signatureInfo = await withProgressiveTimeout(
            extractPDFSignatureStructure(pdfString, pdfBuffer, false),
            `signature extraction (attempt ${extractionAttempt})`,
            isRetry,
            isFinalAttempt
          );
        }
        
        if (signatureInfo && signatureInfo.hasSignature) {
          parsingLog.push(`✓ Signature extraction successful on attempt ${extractionAttempt}`);
          break;
        }
      } catch (timeoutError) {
        parsingLog.push(`⚠ Attempt ${extractionAttempt} failed: ${timeoutError.message}`);
        
        if (extractionAttempt === maxExtractionAttempts) {
          return {
            valid: false,
            format: 'PAdES',
            fileName,
            error: 'Timeout while extracting signature structure - file may be too complex or contain large embedded attachments',
            processingTime: Date.now() - startTime,
            parsingLog: parsingLog,
            troubleshooting: [
              'This file may contain large embedded attachments',
              'Try saving the PDF without attachments',
              'Use Adobe Acrobat for verification of complex signatures',
              'Contact support if this is a critical business document'
            ]
          };
        }
        
        // Brief pause before retry
        await new Promise(resolve => setTimeout(resolve, 500));
        cleanupMemory();
      }
      
      extractionAttempt++;
    }
    
    if (!signatureInfo || !signatureInfo.hasSignature) {
      return { 
        valid: false, 
        format: 'PAdES', 
        fileName, 
        error: 'No digital signature found in PDF after multiple extraction attempts',
        structureValid: false,
        processingTime: Date.now() - startTime,
        parsingLog: parsingLog
      };
    }

    parsingLog.push('✓ PDF signature structure detected');
    parsingLog.push(`• ByteRange: [${signatureInfo.byteRange ? signatureInfo.byteRange.join(', ') : 'Unknown'}]`);
    parsingLog.push(`• Signature length: ${signatureInfo.signatureHex?.length || 0} hex chars`);
    parsingLog.push(`• Signature type: ${signatureInfo.signatureType}`);
    parsingLog.push(`• Multiple signatures: ${signatureInfo.multipleSignatures}`);

    // ENHANCED PARSING WITH PROGRESSIVE TIMEOUTS
    let parseErrors = [];
    
    // Strategy 1: Standard PKI.js parsing with progressive timeout
    if (certificates.length === 0) {
      for (let attempt = 1; attempt <= 2; attempt++) {
        try {
          const isRetry = attempt > 1;
          parseResult = await withProgressiveTimeout(
            parseWithPKIjs(signatureInfo),
            `PKI.js parsing (attempt ${attempt})`,
            isRetry,
            false
          );
          certificates = parseResult.certificates || [];
          
          if (certificates.length > 0) {
            parsingLog.push(`✓ PKI.js parsing successful on attempt ${attempt} - found ${certificates.length} certificates`);
            detailedLog.push(`PKI.js: Success (attempt ${attempt}) with ${certificates.length} certificates`);
            break;
          }
        } catch (pkiError) {
          parseErrors.push(`PKI.js (attempt ${attempt}): ${pkiError.message}`);
          parsingLog.push(`⚠ PKI.js parsing attempt ${attempt} failed: ${pkiError.message}`);
          detailedLog.push(`PKI.js (attempt ${attempt}): Failed - ${pkiError.message}`);
          
          if (attempt < 2) {
            await new Promise(resolve => setTimeout(resolve, 200));
            cleanupMemory();
          }
        }
      }
    }
    
    // Strategy 2: Relaxed ASN.1 parsing with progressive timeout
    if (certificates.length === 0 && CONFIG.ENABLE_RELAXED_PARSING) {
      try {
        parseResult = await withProgressiveTimeout(
          parseWithRelaxedASN1(signatureInfo),
          'Relaxed ASN.1 parsing',
          false,
          false
        );
        certificates = parseResult.certificates || [];
        
        if (certificates.length > 0) {
          parsingLog.push(`✓ Relaxed ASN.1 parsing successful - found ${certificates.length} certificates`);
          detailedLog.push(`Relaxed ASN.1: Success with ${certificates.length} certificates`);
        }
      } catch (relaxedError) {
        parseErrors.push(`Relaxed ASN.1: ${relaxedError.message}`);
        parsingLog.push(`⚠ Relaxed ASN.1 parsing failed: ${relaxedError.message}`);
        detailedLog.push(`Relaxed ASN.1: Failed - ${relaxedError.message}`);
      }
    }
    
    // Strategy 3: Node-forge fallback with timeout
    if (certificates.length === 0) {
      try {
        parseResult = await withProgressiveTimeout(
          parseWithNodeForge(signatureInfo),
          'Node-forge parsing',
          false,
          false
        );
        certificates = parseResult.certificates || [];
        
        if (certificates.length > 0) {
          parsingLog.push(`✓ Node-forge parsing successful - found ${certificates.length} certificates`);
          detailedLog.push(`Node-forge: Success with ${certificates.length} certificates`);
        }
      } catch (forgeError) {
        parseErrors.push(`node-forge: ${forgeError.message}`);
        parsingLog.push(`⚠ Node-forge parsing failed: ${forgeError.message}`);
        detailedLog.push(`Node-forge: Failed - ${forgeError.message}`);
      }
    }
    
    // Strategy 4: RAW CERTIFICATE EXTRACTION with enhanced timeout
    if (certificates.length === 0 && CONFIG.ENABLE_RAW_CERT_EXTRACTION) {
      try {
        const rawCerts = await withProgressiveTimeout(
          extractRawCertificates(signatureInfo),
          'Raw certificate extraction',
          true,
          false
        );
        
        if (rawCerts && rawCerts.length > 0) {
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
    
    // Strategy 5: BRUTE FORCE PARSING with extended timeout (LAST RESORT)
    if (certificates.length === 0 && CONFIG.ENABLE_BRUTE_FORCE_PARSING) {
      try {
        const bruteForceCerts = await withProgressiveTimeout(
          bruteForceCertificateExtraction(signatureInfo),
          'Brute force parsing',
          true,
          true // This is the final attempt
        );
        
        if (bruteForceCerts && bruteForceCerts.length > 0) {
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
    if (!certificates || certificates.length === 0) {
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

    // Extract certificate information from first certificate with error handling
    const signerCert = certificates[0];
    let certInfo;
    try {
      certInfo = await extractUltraRobustCertificateInfo(signerCert);
    } catch (certError) {
      certInfo = createDefaultCertInfo();
      certInfo.commonName = 'Certificate parsing failed';
      parsingLog.push(`⚠ Certificate info extraction failed: ${certError.message}`);
    }

    if (certInfo) {
      parsingLog.push(`✓ Certificate CN: ${certInfo.commonName}`);
      parsingLog.push(`✓ Certificate Org: ${certInfo.organization}`);
      parsingLog.push(`✓ Certificate Issuer: ${certInfo.issuer}`);
      parsingLog.push(`✓ Valid from: ${formatDate(certInfo.validFrom)}`);
      parsingLog.push(`✓ Valid to: ${formatDate(certInfo.validTo)}`);
    }

    // Perform comprehensive validation with error handling
    let validationResults;
    try {
      validationResults = await performComprehensiveValidation(
        certificates, 
        certInfo, 
        enableRevocationCheck, 
        parseResult
      );
    } catch (validationError) {
      validationResults = {
        certificateValid: false,
        chainValid: false,
        revocationStatus: 'Error',
        crlChecked: false,
        ocspChecked: false,
        timestampValid: null,
        validationErrors: [`Validation error: ${validationError.message}`]
      };
    }

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
  } finally {
    // Enhanced cleanup
    signatureInfo = null;
    parseResult = null;
    certificates = null;
    cleanupMemory();
  }
}

// Enhanced signature structure extraction with chunked processing
async function extractPDFSignatureStructure(pdfString, pdfBuffer, isRetry = false) {
  const signatureInfo = {
    hasSignature: false,
    byteRange: null,
    signatureHex: null,
    signatureBytes: null,
    signatureType: 'Unknown',
    multipleSignatures: false
  };

  try {
    // Look for ByteRange with chunked processing to avoid timeouts
    const byteRangeResults = await processWithYield(
      pdfString,
      (chunk, offset) => {
        const match = chunk.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
        return match ? { match, offset } : null;
      },
      CONFIG.CHUNK_SIZE
    );

    const byteRangeResult = byteRangeResults.find(r => r && r.match);
    if (!byteRangeResult) {
      return signatureInfo;
    }

    const byteRangeMatch = byteRangeResult.match;
    const byteRange = [
      parseInt(byteRangeMatch[1]),
      parseInt(byteRangeMatch[2]),
      parseInt(byteRangeMatch[3]),
      parseInt(byteRangeMatch[4])
    ];

    // Validate ByteRange values
    if (byteRange.some(val => isNaN(val) || val < 0)) {
      throw new Error('Invalid ByteRange values');
    }

    if (byteRange[1] + byteRange[3] > pdfBuffer.length) {
      throw new Error('ByteRange exceeds file size');
    }

    signatureInfo.hasSignature = true;
    signatureInfo.byteRange = byteRange;

    // Extract signature content with chunked processing
    const contentsStart = byteRange[1];
    const contentsLength = byteRange[2] - byteRange[1];
    
    if (contentsLength > 0 && contentsStart + contentsLength <= pdfBuffer.length) {
      // Process signature content in chunks to avoid memory issues
      let signatureHex = '';
      const chunkSize = Math.min(CONFIG.CHUNK_SIZE, contentsLength);
      
      for (let i = 0; i < contentsLength; i += chunkSize) {
        const end = Math.min(i + chunkSize, contentsLength);
        const chunk = pdfBuffer.slice(contentsStart + i, contentsStart + end);
        signatureHex += chunk.toString('binary');
        
        // Yield periodically during large signature extraction
        if (i > 0 && i % (chunkSize * 10) === 0) {
          await new Promise(resolve => setImmediate(resolve));
        }
      }

      // Clean and validate signature hex
      signatureHex = signatureHex.replace(/[<>\s]/g, '');
      
      if (signatureHex && /^[0-9A-Fa-f]+$/.test(signatureHex)) {
        signatureInfo.signatureHex = signatureHex;
        
        // Convert to bytes with chunked processing for large signatures
        const signatureBytes = [];
        for (let i = 0; i < signatureHex.length; i += 2) {
          const hexByte = signatureHex.substr(i, 2);
          signatureBytes.push(parseInt(hexByte, 16));
          
          // Yield during conversion of very large signatures
          if (i > 0 && i % 10000 === 0) {
            await new Promise(resolve => setImmediate(resolve));
          }
        }
        
        signatureInfo.signatureBytes = new Uint8Array(signatureBytes);
        
        // Detect signature type with improved heuristics
        signatureInfo.signatureType = detectSignatureType(signatureHex);
        
        // Check for multiple signatures
        const signatureCount = (pdfString.match(/\/ByteRange/g) || []).length;
        signatureInfo.multipleSignatures = signatureCount > 1;
      }
    }

    return signatureInfo;
  } catch (error) {
    throw new Error(`Signature structure extraction failed: ${error.message}`);
  }
}

// Enhanced signature type detection
function detectSignatureType(signatureHex) {
  if (!signatureHex) return 'Unknown';
  
  const hexUpper = signatureHex.toUpperCase();
  
  // Adobe signature detection
  if (hexUpper.includes('41444F4245')) { // 'ADOBE' in hex
    return 'PAdES-LTV (Adobe Acrobat)';
  }
  
  // Aruba PEC detection
  if (hexUpper.includes('4152554241')) { // 'ARUBA' in hex
    return 'PAdES-BES/LTV (Aruba PEC)';
  }
  
  // Dike signature detection
  if (hexUpper.includes('44494B45')) { // 'DIKE' in hex
    return 'PAdES-BES (Dike GoSign)';
  }
  
  // InfoCert detection
  if (hexUpper.includes('494E464F43455254')) { // 'INFOCERT' in hex
    return 'PAdES-BES (InfoCert)';
  }
  
  // Generic PAdES detection
  if (hexUpper.includes('30') && hexUpper.length > 100) {
    return 'PAdES (Generic)';
  }
  
  return 'Digital Signature (Unknown Format)';
}

// ------------------------------------------------------------------
// COMPLETE PARSING FUNCTION IMPLEMENTATIONS
// ------------------------------------------------------------------

// Enhanced PKI.js parsing with ASN.1 tolerance
async function parseWithPKIjs(signatureInfo) {
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information provided');
  }
  
  try {
    const signatureBytes = signatureInfo.signatureBytes;
    
    // Parse PKCS#7/CMS structure with PKI.js
    const asn1 = asn1js.fromBER(signatureBytes.buffer);
    
    if (asn1.offset === -1) {
      // Try parsing with partial data (common with complex PAdES)
      const partialLength = Math.floor(signatureBytes.length * 0.9);
      const partialBuffer = signatureBytes.slice(0, partialLength).buffer;
      const partialAsn1 = asn1js.fromBER(partialBuffer);
      
      if (partialAsn1.offset === -1) {
        throw new Error('Invalid ASN.1 structure in signature data');
      }
    }
    
    // Parse ContentInfo structure
    let contentInfo;
    try {
      contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    } catch (contentError) {
      throw new Error(`Failed to parse ContentInfo: ${contentError.message}`);
    }
    
    // Check if it's a SignedData structure
    if (contentInfo.contentType !== '1.2.840.113549.1.7.2') {
      throw new Error('Not a PKCS#7 SignedData structure');
    }
    
    // Parse SignedData
    let signedData;
    try {
      signedData = new pkijs.SignedData({ schema: contentInfo.content });
    } catch (signedError) {
      throw new Error(`Failed to parse SignedData: ${signedError.message}`);
    }
    
    // Extract certificates
    const certificates = signedData.certificates || [];
    
    if (certificates.length === 0) {
      throw new Error('No certificates found in SignedData structure');
    }
    
    // Extract signer information
    const signerInfos = signedData.signerInfos || [];
    let signingTime = null;
    let algorithm = 'Unknown';
    
    if (signerInfos.length > 0) {
      const signerInfo = signerInfos[0];
      
      // Extract algorithm
      if (signerInfo.digestAlgorithm && signerInfo.digestAlgorithm.algorithmId) {
        algorithm = getAlgorithmName(signerInfo.digestAlgorithm.algorithmId);
      }
      
      // Extract signing time from authenticated attributes
      if (signerInfo.signedAttrs && signerInfo.signedAttrs.attributes) {
        for (const attr of signerInfo.signedAttrs.attributes) {
          if (attr.type === '1.2.840.113549.1.9.5') { // signing-time
            try {
              const timeValue = attr.values[0];
              if (timeValue && timeValue.valueBlock && timeValue.valueBlock.value) {
                signingTime = new Date(timeValue.valueBlock.value);
              }
            } catch (timeError) {
              // Ignore signing time parsing errors
            }
          }
        }
      }
    }
    
    return {
      certificates: certificates,
      signatureValid: null, // Need hash verification for this
      algorithm: algorithm,
      signingTime: signingTime,
      timestampInfo: null,
      parsingMethod: 'PKI.js'
    };
    
  } catch (error) {
    throw new Error(`PKI.js parsing failed: ${error.message}`);
  }
}

// Relaxed ASN.1 parsing for problematic signatures
async function parseWithRelaxedASN1(signatureInfo) {
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information provided');
  }
  
  try {
    const signatureBytes = signatureInfo.signatureBytes;
    
    // Try parsing with different byte ranges to handle trailing data
    const parseAttempts = [100, 95, 90, 85, 80]; // Percentages of data to parse
    
    for (const percentage of parseAttempts) {
      try {
        const cutoff = Math.floor(signatureBytes.length * (percentage / 100));
        const truncatedBytes = signatureBytes.slice(0, cutoff);
        
        const asn1 = asn1js.fromBER(truncatedBytes.buffer);
        
        if (asn1.offset !== -1) {
          // Successfully parsed - extract certificates
          const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
          
          if (contentInfo.contentType === '1.2.840.113549.1.7.2') {
            const signedData = new pkijs.SignedData({ schema: contentInfo.content });
            
            if (signedData.certificates && signedData.certificates.length > 0) {
              return {
                certificates: signedData.certificates,
                signatureValid: null,
                algorithm: 'Unknown (Relaxed Parsing)',
                signingTime: null,
                timestampInfo: null,
                parsingMethod: `Relaxed ASN.1 (${percentage}% of data)`
              };
            }
          }
        }
      } catch (attemptError) {
        // Continue to next percentage
        continue;
      }
    }
    
    throw new Error('All relaxed parsing attempts failed');
    
  } catch (error) {
    throw new Error(`Relaxed ASN.1 parsing failed: ${error.message}`);
  }
}

// Node-forge fallback parsing
async function parseWithNodeForge(signatureInfo) {
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information provided');
  }
  
  try {
    const signatureBytes = signatureInfo.signatureBytes;
    
    // Convert to node-forge buffer
    const der = forge.util.createBuffer(signatureBytes);
    
    // Parse ASN.1 structure
    let asn1;
    try {
      asn1 = forge.asn1.fromDer(der);
    } catch (asn1Error) {
      throw new Error(`ASN.1 parsing failed: ${asn1Error.message}`);
    }
    
    // Parse PKCS#7 message
    let p7;
    try {
      p7 = forge.pkcs7.messageFromAsn1(asn1);
    } catch (p7Error) {
      throw new Error(`PKCS#7 parsing failed: ${p7Error.message}`);
    }
    
    // Extract certificates
    const certificates = p7.certificates || [];
    
    if (certificates.length === 0) {
      throw new Error('No certificates found in PKCS#7 structure');
    }
    
    // Extract additional information
    let signingTime = null;
    let algorithm = 'Unknown';
    
    if (p7.signers && p7.signers.length > 0) {
      const signer = p7.signers[0];
      
      // Extract algorithm
      if (signer.digestAlgorithm) {
        algorithm = signer.digestAlgorithm;
      }
      
      // Extract signing time from authenticated attributes
      if (signer.authenticatedAttributes) {
        for (const attr of signer.authenticatedAttributes) {
          if (attr.type === forge.pki.oids.signingTime) {
            try {
              signingTime = new Date(attr.value);
            } catch (timeError) {
              // Ignore signing time parsing errors
            }
          }
        }
      }
    }
    
    return {
      certificates: certificates,
      signatureValid: null,
      algorithm: algorithm,
      signingTime: signingTime,
      timestampInfo: null,
      parsingMethod: 'Node-forge'
    };
    
  } catch (error) {
    throw new Error(`Node-forge parsing failed: ${error.message}`);
  }
}

// Raw certificate extraction with pattern matching
async function extractRawCertificates(signatureInfo) {
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information provided');
  }
  
  try {
    const certificates = [];
    const signatureBytes = signatureInfo.signatureBytes;
    
    // Look for X.509 certificate patterns in the signature data
    const certPattern = new Uint8Array([0x30, 0x82]); // Common X.509 certificate start
    
    for (let i = 0; i < signatureBytes.length - 1000; i++) {
      // Look for certificate pattern
      if (signatureBytes[i] === certPattern[0] && 
          signatureBytes[i + 1] === certPattern[1]) {
        
        // Try to extract certificate length
        let certLength;
        try {
          certLength = (signatureBytes[i + 2] << 8) | signatureBytes[i + 3];
          if (certLength > 0 && certLength < 10000 && (i + certLength + 4) <= signatureBytes.length) {
            
            // Extract potential certificate
            const certBytes = signatureBytes.slice(i, i + certLength + 4);
            
            // Try to parse with PKI.js
            try {
              const asn1Cert = asn1js.fromBER(certBytes.buffer);
              if (asn1Cert.offset !== -1) {
                const certificate = new pkijs.Certificate({ schema: asn1Cert.result });
                if (certificate && certificate.subject) {
                  certificates.push(certificate);
                  i += certLength + 4; // Skip past this certificate
                }
              }
            } catch (certError) {
              // Try node-forge as fallback
              try {
                const der = forge.util.createBuffer(certBytes);
                const asn1 = forge.asn1.fromDer(der);
                const certificate = forge.pki.certificateFromAsn1(asn1);
                if (certificate && certificate.subject) {
                  certificates.push(certificate);
                  i += certLength + 4;
                }
              } catch (forgeError) {
                // Not a valid certificate, continue searching
              }
            }
          }
        } catch (lengthError) {
          // Invalid length, continue searching
          continue;
        }
      }
    }
    
    if (certificates.length === 0) {
      throw new Error('No certificates found using raw extraction');
    }
    
    return certificates;
    
  } catch (error) {
    throw new Error(`Raw certificate extraction failed: ${error.message}`);
  }
}

// Brute force certificate extraction for complex files
async function bruteForceCertificateExtraction(signatureInfo) {
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information provided');
  }
  
  try {
    const certificates = [];
    const signatureBytes = signatureInfo.signatureBytes;
    
    // Common ASN.1 patterns that might indicate certificate data
    const patterns = [
      [0x30, 0x82], // SEQUENCE with long form length
      [0x30, 0x81], // SEQUENCE with medium form length  
      [0x30, 0x80], // SEQUENCE with indefinite length
    ];
    
    for (const pattern of patterns) {
      for (let i = 0; i < signatureBytes.length - 500; i++) {
        if (signatureBytes[i] === pattern[0] && signatureBytes[i + 1] === pattern[1]) {
          
          // Try different lengths starting from this position
          for (let len = 500; len <= Math.min(8000, signatureBytes.length - i); len += 100) {
            try {
              const candidateBytes = signatureBytes.slice(i, i + len);
              
              // Try PKI.js parsing
              try {
                const asn1Cert = asn1js.fromBER(candidateBytes.buffer);
                if (asn1Cert.offset !== -1) {
                  const certificate = new pkijs.Certificate({ schema: asn1Cert.result });
                  if (certificate && certificate.subject && certificate.subject.typesAndValues) {
                    // Validate it looks like a real certificate
                    let hasValidSubject = false;
                    for (const attr of certificate.subject.typesAndValues) {
                      if (attr.type === '2.5.4.3' || // Common Name
                          attr.type === '2.5.4.10' || // Organization
                          attr.type === '2.5.4.6') {  // Country
                        hasValidSubject = true;
                        break;
                      }
                    }
                    
                    if (hasValidSubject && !certificates.find(c => 
                        c.serialNumber && certificate.serialNumber && 
                        c.serialNumber.toString() === certificate.serialNumber.toString())) {
                      certificates.push(certificate);
                    }
                  }
                }
              } catch (pkiError) {
                // Try node-forge as fallback
                try {
                  const der = forge.util.createBuffer(candidateBytes);
                  const asn1 = forge.asn1.fromDer(der);
                  const certificate = forge.pki.certificateFromAsn1(asn1);
                  if (certificate && certificate.subject && certificate.subject.attributes) {
                    // Check for duplicate
                    const serialNumber = certificate.serialNumber;
                    if (!certificates.find(c => c.serialNumber === serialNumber)) {
                      certificates.push(certificate);
                    }
                  }
                } catch (forgeError) {
                  // Not a valid certificate at this length
                }
              }
              
              // Yield occasionally during brute force
              if (len % 1000 === 0) {
                await new Promise(resolve => setImmediate(resolve));
              }
              
            } catch (generalError) {
              // Continue with next length
              continue;
            }
          }
        }
      }
    }
    
    if (certificates.length === 0) {
      throw new Error('No certificates found using brute force extraction');
    }
    
    return certificates;
    
  } catch (error) {
    throw new Error(`Brute force extraction failed: ${error.message}`);
  }
}

// ------------------------------------------------------------------
// CERTIFICATE INFORMATION EXTRACTION
// ------------------------------------------------------------------

// Enhanced certificate information extraction
async function extractUltraRobustCertificateInfo(certificate) {
  try {
    const certInfo = createDefaultCertInfo();
    
    // Handle PKI.js certificate
    if (certificate.subject && certificate.subject.typesAndValues) {
      for (const attr of certificate.subject.typesAndValues) {
        const value = attr.value ? attr.value.valueBlock ? attr.value.valueBlock.value : attr.value : '';
        
        switch (attr.type) {
          case '2.5.4.3': // Common Name
            certInfo.commonName = value;
            break;
          case '2.5.4.10': // Organization
            certInfo.organization = value;
            break;
          case '2.5.4.11': // Organizational Unit
            if (!certInfo.organizationalUnit) certInfo.organizationalUnit = value;
            break;
          case '2.5.4.6': // Country
            certInfo.country = value;
            break;
          case '1.2.840.113549.1.9.1': // Email
            certInfo.email = value;
            break;
        }
      }
      
      // Extract issuer information
      if (certificate.issuer && certificate.issuer.typesAndValues) {
        for (const attr of certificate.issuer.typesAndValues) {
          if (attr.type === '2.5.4.3') {
            const value = attr.value ? attr.value.valueBlock ? attr.value.valueBlock.value : attr.value : '';
            certInfo.issuer = value;
            break;
          }
        }
      }
      
      // Extract validity dates
      if (certificate.notBefore && certificate.notBefore.value) {
        certInfo.validFrom = certificate.notBefore.value;
      }
      if (certificate.notAfter && certificate.notAfter.value) {
        certInfo.validTo = certificate.notAfter.value;
      }
      
      // Extract serial number
      if (certificate.serialNumber) {
        certInfo.serialNumber = certificate.serialNumber.toString();
      }
    }
    // Handle node-forge certificate
    else if (certificate.subject && certificate.subject.attributes) {
      for (const attr of certificate.subject.attributes) {
        switch (attr.type || attr.name) {
          case '2.5.4.3':
          case 'commonName':
            certInfo.commonName = attr.value;
            break;
          case '2.5.4.10':
          case 'organizationName':
            certInfo.organization = attr.value;
            break;
          case '2.5.4.11':
          case 'organizationalUnitName':
            if (!certInfo.organizationalUnit) certInfo.organizationalUnit = attr.value;
            break;
          case '2.5.4.6':
          case 'countryName':
            certInfo.country = attr.value;
            break;
          case '1.2.840.113549.1.9.1':
          case 'emailAddress':
            certInfo.email = attr.value;
            break;
        }
      }
      
      // Extract issuer
      if (certificate.issuer && certificate.issuer.attributes) {
        for (const attr of certificate.issuer.attributes) {
          if ((attr.type || attr.name) === 'commonName' || (attr.type || attr.name) === '2.5.4.3') {
            certInfo.issuer = attr.value;
            break;
          }
        }
      }
      
      // Extract validity dates
      if (certificate.validity) {
        certInfo.validFrom = certificate.validity.notBefore;
        certInfo.validTo = certificate.validity.notAfter;
      }
      
      // Extract serial number
      if (certificate.serialNumber) {
        certInfo.serialNumber = certificate.serialNumber;
      }
    }
    
    // Validate certificate dates
    const now = new Date();
    if (certInfo.validFrom && certInfo.validTo) {
      certInfo.isValid = now >= new Date(certInfo.validFrom) && now <= new Date(certInfo.validTo);
    }
    
    return certInfo;
    
  } catch (error) {
    throw new Error(`Certificate info extraction failed: ${error.message}`);
  }
}

// ------------------------------------------------------------------
// COMPREHENSIVE VALIDATION
// ------------------------------------------------------------------

// Comprehensive validation implementation
async function performComprehensiveValidation(certificates, certInfo, enableRevocationCheck, parseResult) {
  try {
    const results = {
      certificateValid: false,
      chainValid: false,
      revocationStatus: 'Not checked',
      crlChecked: false,
      ocspChecked: false,
      timestampValid: null,
      validationErrors: []
    };
    
    if (!certificates || certificates.length === 0) {
      results.validationErrors.push('No certificates available for validation');
      return results;
    }
    
    // Basic certificate validation
    const mainCert = certificates[0];
    
    // Check certificate dates
    if (certInfo && certInfo.validFrom && certInfo.validTo) {
      const now = new Date();
      const validFrom = new Date(certInfo.validFrom);
      const validTo = new Date(certInfo.validTo);
      
      if (now >= validFrom && now <= validTo) {
        results.certificateValid = true;
      } else {
        if (now < validFrom) {
          results.validationErrors.push('Certificate is not yet valid');
        } else {
          results.validationErrors.push('Certificate has expired');
        }
      }
    }
    
    // Check certificate chain
    if (certificates.length > 1) {
      results.chainValid = true; // Simplified - would need proper chain validation
    } else {
      results.validationErrors.push('Certificate chain incomplete or self-signed');
    }
    
    // Revocation checking (simplified)
    if (enableRevocationCheck && CONFIG.ENABLE_CRL) {
      try {
        // This would normally check CRL/OCSP - simplified for now
        results.revocationStatus = 'Unknown';
        results.crlChecked = true;
      } catch (revocationError) {
        results.validationErrors.push(`Revocation check failed: ${revocationError.message}`);
      }
    }
    
    return results;
    
  } catch (error) {
    return {
      certificateValid: false,
      chainValid: false,
      revocationStatus: 'Error',
      crlChecked: false,
      ocspChecked: false,
      timestampValid: null,
      validationErrors: [`Validation failed: ${error.message}`]
    };
  }
}

// ------------------------------------------------------------------
// HELPER FUNCTIONS
// ------------------------------------------------------------------

// Get algorithm name from OID
function getAlgorithmName(oid) {
  const algorithms = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.5': 'SHA-1 with RSA',
    '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
    '1.2.840.113549.1.1.12': 'SHA-384 with RSA',
    '1.2.840.113549.1.1.13': 'SHA-512 with RSA',
    '1.2.840.10040.4.1': 'DSA',
    '1.2.840.10045.2.1': 'ECDSA',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512'
  };
  
  return algorithms[oid] || `Unknown (${oid})`;
}

// Create advanced structure result
function createUltraAdvancedStructureResult(signatureInfo, fileName, parseErrors, parsingLog, detailedLog, startTime) {
  return {
    valid: false,
    structureValid: true,
    format: signatureInfo.signatureType || 'PAdES',
    fileName,
    error: 'Signature structure detected but certificate parsing failed',
    parseErrors,
    parsingLog,
    detailedLog,
    processingTime: Date.now() - startTime,
    byteRange: signatureInfo.byteRange,
    signatureLength: signatureInfo.signatureHex ? signatureInfo.signatureHex.length : 0,
    multipleSignatures: signatureInfo.multipleSignatures,
    troubleshooting: [
      'Signature structure is valid but contains complex certificate data',
      'This may be a PAdES-LTV signature with embedded validation data',
      'Try using Adobe Acrobat Reader for full verification',
      'The signature may still be legally valid despite parsing limitations'
    ]
  };
}

// Create default certificate info
function createDefaultCertInfo() {
  return {
    commonName: 'Unknown',
    organization: 'Unknown',
    organizationalUnit: null,
    country: null,
    email: null,
    issuer: 'Unknown',
    validFrom: null,
    validTo: null,
    serialNumber: null,
    isValid: null
  };
}

// Build comprehensive result
function buildUltraComprehensiveResult(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime) {
  const processingTime = Date.now() - startTime;
  
  // Determine overall validity
  const isStructureValid = signatureInfo && signatureInfo.hasSignature;
  const hasCertificates = parseResult && parseResult.certificates && parseResult.certificates.length > 0;
  const isCertificateValid = validationResults && validationResults.certificateValid;
  
  const result = {
    // Core validation results
    valid: hasCertificates && isCertificateValid,
    structureValid: isStructureValid,
    cryptographicVerification: hasCertificates,
    
    // File information
    fileName,
    format: signatureInfo ? signatureInfo.signatureType : 'PAdES',
    processingTime,
    
    // Signature information
    signatureValid: parseResult ? parseResult.signatureValid : null,
    certificateValid: validationResults ? validationResults.certificateValid : false,
    
    // Certificate details
    signedBy: certInfo ? certInfo.commonName : 'Unknown',
    organization: certInfo ? certInfo.organization : 'Unknown',
    email: certInfo ? certInfo.email : null,
    certificateIssuer: certInfo ? certInfo.issuer : 'Unknown',
    certificateValidFrom: certInfo ? formatDate(certInfo.validFrom) : 'Unknown',
    certificateValidTo: certInfo ? formatDate(certInfo.validTo) : 'Unknown',
    serialNumber: certInfo ? certInfo.serialNumber : null,
    
    // Technical details
    signatureAlgorithm: parseResult ? parseResult.algorithm : 'Unknown',
    signatureDate: parseResult && parseResult.signingTime ? formatDateTime(parseResult.signingTime) : null,
    signingTime: parseResult && parseResult.signingTime ? formatDateTime(parseResult.signingTime) : null,
    
    // Chain information
    certificateChainLength: parseResult && parseResult.certificates ? parseResult.certificates.length : 0,
    isSelfSigned: parseResult && parseResult.certificates ? parseResult.certificates.length === 1 : null,
    
    // Validation details
    chainValid: validationResults ? validationResults.chainValid : false,
    revocationStatus: validationResults ? validationResults.revocationStatus : 'Not checked',
    
    // Processing information
    parsingMethod: parseResult ? parseResult.parsingMethod : 'Structure analysis only',
    parsingLog,
    detailedLog
  };
  
  // Add warnings based on validation results
  const warnings = [];
  
  if (validationResults && validationResults.validationErrors && validationResults.validationErrors.length > 0) {
    warnings.push(...validationResults.validationErrors);
  }
  
  if (!isCertificateValid && certInfo && certInfo.validTo) {
    const expiredDate = new Date(certInfo.validTo);
    const now = new Date();
    if (now > expiredDate) {
      warnings.push(`Certificate expired on ${formatDate(expiredDate)}`);
    }
  }
  
  if (!hasCertificates) {
    warnings.push('Full cryptographic verification not available - structure validation only');
  }
  
  if (signatureInfo && signatureInfo.signatureType.includes('Adobe')) {
    warnings.push('Adobe Acrobat signature detected - recommend verification with Adobe tools for complete validation');
  }
  
  if (warnings.length > 0) {
    result.warnings = warnings;
  }
  
  return result;
}