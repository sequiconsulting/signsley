// verify-pades.js (v7 Enhanced with improved error handling and memory management)
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

// Enhanced Configuration
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
  // New timeout and memory management
  PARSE_TIMEOUT: 5000, // 5 seconds max per parsing strategy
  MAX_MEMORY_MB: 256, // 256MB memory limit
  CLEANUP_INTERVAL: 1000 // Cleanup every second
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

// Memory cleanup helper
function cleanupMemory() {
  if (global.gc) {
    try {
      global.gc();
    } catch (e) {
      // Ignore GC errors
    }
  }
}

// Timeout wrapper for parsing strategies
async function withTimeout(promise, timeoutMs, operation) {
  return Promise.race([
    promise,
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error(`${operation} timeout after ${timeoutMs}ms`)), timeoutMs)
    )
  ]);
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
      message: 'The file is taking too long to process. Please try again with a smaller file or contact support.'
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
      message: 'Unable to process the digital signature. The file may not contain a valid signature.'
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
// ENHANCED MAIN VERIFICATION WITH IMPROVED ERROR HANDLING
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

    // Extract signature structure with timeout
    try {
      signatureInfo = await withTimeout(
        extractPDFSignatureStructure(pdfString, pdfBuffer),
        CONFIG.PARSE_TIMEOUT,
        'signature extraction'
      );
    } catch (timeoutError) {
      return {
        valid: false,
        format: 'PAdES',
        fileName,
        error: 'Timeout while extracting signature structure',
        processingTime: Date.now() - startTime
      };
    }
    
    if (!signatureInfo || !signatureInfo.hasSignature) {
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
    parsingLog.push(`• ByteRange: [${signatureInfo.byteRange ? signatureInfo.byteRange.join(', ') : 'Unknown'}]`);
    parsingLog.push(`• Signature length: ${signatureInfo.signatureHex?.length || 0} hex chars`);
    parsingLog.push(`• Signature type: ${signatureInfo.signatureType}`);
    parsingLog.push(`• Multiple signatures: ${signatureInfo.multipleSignatures}`);

    // ENHANCED PARSING WITH MULTIPLE STRATEGIES AND TIMEOUTS
    let parseErrors = [];
    
    // Strategy 1: Standard PKI.js parsing with timeout
    if (certificates.length === 0) {
      try {
        parseResult = await withTimeout(
          parseWithPKIjs(signatureInfo),
          CONFIG.PARSE_TIMEOUT,
          'PKI.js parsing'
        );
        certificates = parseResult.certificates || [];
        parsingLog.push(`✓ PKI.js parsing successful - found ${certificates.length} certificates`);
        detailedLog.push(`PKI.js: Success with ${certificates.length} certificates`);
      } catch (pkiError) {
        parseErrors.push(`PKI.js: ${pkiError.message}`);
        parsingLog.push(`⚠ PKI.js parsing failed: ${pkiError.message}`);
        detailedLog.push(`PKI.js: Failed - ${pkiError.message}`);
      }
    }
    
    // Strategy 2: Relaxed ASN.1 parsing with timeout
    if (certificates.length === 0 && CONFIG.ENABLE_RELAXED_PARSING) {
      try {
        parseResult = await withTimeout(
          parseWithRelaxedASN1(signatureInfo),
          CONFIG.PARSE_TIMEOUT,
          'Relaxed ASN.1 parsing'
        );
        certificates = parseResult.certificates || [];
        parsingLog.push(`✓ Relaxed ASN.1 parsing successful - found ${certificates.length} certificates`);
        detailedLog.push(`Relaxed ASN.1: Success with ${certificates.length} certificates`);
      } catch (relaxedError) {
        parseErrors.push(`Relaxed ASN.1: ${relaxedError.message}`);
        parsingLog.push(`⚠ Relaxed ASN.1 parsing failed: ${relaxedError.message}`);
        detailedLog.push(`Relaxed ASN.1: Failed - ${relaxedError.message}`);
      }
    }
    
    // Strategy 3: Node-forge fallback with timeout
    if (certificates.length === 0) {
      try {
        parseResult = await withTimeout(
          parseWithNodeForge(signatureInfo),
          CONFIG.PARSE_TIMEOUT,
          'Node-forge parsing'
        );
        certificates = parseResult.certificates || [];
        parsingLog.push(`✓ Node-forge parsing successful - found ${certificates.length} certificates`);
        detailedLog.push(`Node-forge: Success with ${certificates.length} certificates`);
      } catch (forgeError) {
        parseErrors.push(`node-forge: ${forgeError.message}`);
        parsingLog.push(`⚠ Node-forge parsing failed: ${forgeError.message}`);
        detailedLog.push(`Node-forge: Failed - ${forgeError.message}`);
      }
    }
    
    // Strategy 4: RAW CERTIFICATE EXTRACTION with timeout
    if (certificates.length === 0 && CONFIG.ENABLE_RAW_CERT_EXTRACTION) {
      try {
        const rawCerts = await withTimeout(
          extractRawCertificates(signatureInfo),
          CONFIG.PARSE_TIMEOUT,
          'Raw certificate extraction'
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
    
    // Strategy 5: BRUTE FORCE PARSING with timeout (LAST RESORT)
    if (certificates.length === 0 && CONFIG.ENABLE_BRUTE_FORCE_PARSING) {
      try {
        const bruteForceCerts = await withTimeout(
          bruteForceCertificateExtraction(signatureInfo),
          CONFIG.PARSE_TIMEOUT * 2, // Allow more time for brute force
          'Brute force parsing'
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

// Rest of the functions remain the same but with enhanced error handling...
// [The rest of the file continues with the same functions but I'll include the key improvements]

// Enhanced certificate extraction with better error handling
async function extractRawCertificates(signatureInfo) {
  if (!signatureInfo || !signatureInfo.signatureBytes) {
    throw new Error('Invalid signature information provided');
  }
  
  const certificates = [];
  const signatureBytes = signatureInfo.signatureBytes;
  
  try {
    // Validate signature bytes
    if (!signatureBytes || signatureBytes.length === 0) {
      throw new Error('Empty or invalid signature bytes');
    }
    
    const certificateMarkers = findCertificateMarkers(signatureBytes);
    
    for (const marker of certificateMarkers) {
      if (!marker || typeof marker.start !== 'number' || typeof marker.end !== 'number') {
        continue;
      }
      
      try {
        const certBytes = signatureBytes.slice(marker.start, marker.end);
        
        if (!certBytes || certBytes.length === 0) {
          continue;
        }
        
        // Try to parse as PKI.js certificate
        try {
          const asn1Cert = asn1js.fromBER(certBytes.buffer);
          if (asn1Cert && asn1Cert.offset !== -1) {
            const certificate = new pkijs.Certificate({ schema: asn1Cert.result });
            if (certificate) {
              certificates.push(certificate);
              continue;
            }
          }
        } catch (pkiError) {
          // Try node-forge as fallback
          try {
            const der = forge.util.createBuffer(certBytes);
            const asn1 = forge.asn1.fromDer(der);
            const certificate = forge.pki.certificateFromAsn1(asn1);
            if (certificate) {
              certificates.push(certificate);
            }
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

// [Continue with remaining helper functions with similar error handling improvements...]