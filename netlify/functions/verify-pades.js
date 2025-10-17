// verify-pades.js (v8 Enhanced with progressive timeout handling)
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

// Placeholder functions - these would contain the actual parsing logic
// These are simplified versions for the fix

async function parseWithPKIjs(signatureInfo) {
  // Enhanced PKI.js parsing with better error handling
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information');
  }
  
  try {
    const asn1 = asn1js.fromBER(signatureInfo.signatureBytes.buffer);
    if (asn1.offset === -1) {
      throw new Error('Invalid ASN.1 structure');
    }
    
    // Continue with PKI.js parsing...
    return {
      certificates: [],
      signatureValid: null,
      algorithm: 'Unknown',
      signingTime: null,
      parsingMethod: 'PKI.js'
    };
  } catch (error) {
    throw new Error(`PKI.js parsing failed: ${error.message}`);
  }
}

async function parseWithRelaxedASN1(signatureInfo) {
  // Relaxed ASN.1 parsing implementation
  throw new Error('Relaxed ASN.1 parsing not yet implemented in this version');
}

async function parseWithNodeForge(signatureInfo) {
  // Node-forge parsing implementation
  throw new Error('Node-forge parsing not yet implemented in this version');
}

async function extractRawCertificates(signatureInfo) {
  // Raw certificate extraction implementation
  throw new Error('Raw certificate extraction not yet implemented in this version');
}

async function bruteForceCertificateExtraction(signatureInfo) {
  // Brute force certificate extraction implementation
  throw new Error('Brute force extraction not yet implemented in this version');
}

// Placeholder helper functions
function createUltraAdvancedStructureResult(signatureInfo, fileName, parseErrors, parsingLog, detailedLog, startTime) {
  return {
    valid: false,
    structureValid: true,
    format: signatureInfo.signatureType || 'PAdES',
    fileName,
    error: 'Signature structure detected but parsing failed',
    parseErrors,
    parsingLog,
    detailedLog,
    processingTime: Date.now() - startTime
  };
}

function createDefaultCertInfo() {
  return {
    commonName: 'Unknown',
    organization: 'Unknown',
    issuer: 'Unknown',
    validFrom: null,
    validTo: null
  };
}

async function extractUltraRobustCertificateInfo(certificate) {
  // Certificate information extraction implementation
  return createDefaultCertInfo();
}

async function performComprehensiveValidation(certificates, certInfo, enableRevocationCheck, parseResult) {
  // Validation implementation
  return {
    certificateValid: false,
    chainValid: false,
    revocationStatus: 'Not checked',
    crlChecked: false,
    ocspChecked: false,
    timestampValid: null,
    validationErrors: []
  };
}

function buildUltraComprehensiveResult(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime) {
  return {
    valid: false,
    structureValid: true,
    format: signatureInfo.signatureType || 'PAdES',
    fileName,
    processingTime: Date.now() - startTime,
    parsingLog,
    detailedLog
  };
}