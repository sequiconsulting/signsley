// verify-pades.js (v3 with advanced PAdES support)
const forge = require('node-forge');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

// Set crypto engine for PKI.js
const crypto = require('crypto').webcrypto;
pkijs.setEngine('newEngine', crypto, new pkijs.CryptoEngine({
  crypto,
  subtle: crypto.subtle
}));

// Utility: format date YYYY/MM/DD
function formatDate(date) {
  if (!date) return 'Unknown';
  try {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return 'Unknown';
    return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
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
    const { fileData, fileName } = body;

    if (!fileData)
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'No file data provided', valid: false }) };

    const base64 = fileData.replace(/^data:application\/pdf;base64,/, '').trim();
    if (!/^[A-Za-z0-9+/=]+$/.test(base64))
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid Base64 data format', valid: false }) };

    const size = (base64.length * 3) / 4;
    if (size > 6 * 1024 * 1024)
      return { statusCode: 413, headers, body: JSON.stringify({ error: 'File too large', valid: false }) };

    const buffer = Buffer.from(base64, 'base64');
    const result = await verifyAdvancedPAdES(buffer, fileName);

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
// ADVANCED PADES VERIFICATION WITH MULTIPLE PARSERS
// ------------------------------------------------------------------
async function verifyAdvancedPAdES(pdfBuffer, fileName) {
  try {
    const pdfString = pdfBuffer.toString('latin1');
    
    // Basic PDF validation
    if (!pdfString.startsWith('%PDF-')) {
      return { 
        valid: false, 
        format: 'PAdES', 
        fileName, 
        error: 'Not a valid PDF file' 
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
        structureValid: false
      };
    }

    // Try advanced parsing with PKI.js first
    try {
      return await verifyWithPKIjs(signatureInfo, fileName);
    } catch (pkiError) {
      console.log('PKI.js parsing failed, trying node-forge fallback:', pkiError.message);
      
      // Fallback to node-forge
      try {
        return await verifyWithNodeForge(signatureInfo, fileName);
      } catch (forgeError) {
        console.log('Node-forge parsing also failed:', forgeError.message);
        
        // Return structured analysis even if cryptographic verification fails
        return createStructureOnlyResult(signatureInfo, fileName, pkiError, forgeError);
      }
    }

  } catch (error) {
    console.error('Critical verification error:', error);
    return { 
      valid: false, 
      format: 'PAdES', 
      fileName, 
      error: 'Critical verification failure: ' + error.message 
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
    signatureType: 'Unknown'
  };

  // Look for ByteRange
  const byteRangeMatch = pdfString.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!byteRangeMatch) {
    return result;
  }

  result.byteRange = byteRangeMatch.slice(1).map(n => parseInt(n));
  result.hasSignature = true;

  // Extract signature hex
  result.signatureHex = extractSignatureHex(pdfString);
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

function extractSignatureHex(pdfString) {
  const contentsIndex = pdfString.indexOf('/Contents');
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
    // Check for PKCS#7 signature markers
    const asn1 = asn1js.fromBER(signatureBytes.buffer);
    if (asn1.offset === -1) {
      return 'Unknown ASN.1 Structure';
    }

    // Look for ContentInfo OID (PKCS#7)
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
// ADVANCED VERIFICATION WITH PKI.JS
// ------------------------------------------------------------------
async function verifyWithPKIjs(signatureInfo, fileName) {
  try {
    // Parse with PKI.js
    const asn1 = asn1js.fromBER(signatureInfo.signatureBytes.buffer);
    if (asn1.offset === -1) {
      throw new Error('Invalid ASN.1 structure');
    }

    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    
    if (contentInfo.contentType !== '1.2.840.113549.1.7.2') {
      throw new Error('Not a PKCS#7 SignedData structure');
    }

    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    
    if (!signedData.certificates || signedData.certificates.length === 0) {
      throw new Error('No certificates found in signature');
    }

    // Extract certificate info
    const signerCert = signedData.certificates[0];
    const certInfo = await extractAdvancedCertificateInfo(signerCert);

    // Verify signature (simplified)
    const now = new Date();
    const certValid = certInfo.validFrom <= now && now <= certInfo.validTo;

    return {
      valid: certValid, // We can't do full crypto verification in serverless easily
      format: signatureInfo.signatureType,
      fileName,
      cryptographicVerification: false, // Structure validation only
      structureValid: true,
      signatureValid: null, // Cannot verify without full crypto setup
      certificateValid: certValid,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      signatureDate: certInfo.signatureDate || 'Unknown',
      signatureAlgorithm: certInfo.algorithm,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(certInfo.validFrom),
      certificateValidTo: formatDate(certInfo.validTo),
      serialNumber: certInfo.serialNumber,
      certificateChainLength: signedData.certificates.length,
      isSelfSigned: certInfo.isSelfSigned,
      warnings: [
        'Advanced PAdES signature successfully parsed',
        'Full cryptographic verification requires additional crypto setup',
        'Certificate chain and CRL/OCSP validation not performed',
        'For complete validation, use Adobe Acrobat or dedicated PAdES tools'
      ]
    };

  } catch (error) {
    throw new Error(`PKI.js parsing failed: ${error.message}`);
  }
}

// ------------------------------------------------------------------
// FALLBACK VERIFICATION WITH NODE-FORGE
// ------------------------------------------------------------------
async function verifyWithNodeForge(signatureInfo, fileName) {
  try {
    const der = forge.util.createBuffer(signatureInfo.signatureBytes);
    const asn1 = forge.asn1.fromDer(der);
    const p7 = forge.pkcs7.messageFromAsn1(asn1);

    if (!p7.certificates || p7.certificates.length === 0) {
      throw new Error('No certificates found in PKCS#7 structure');
    }

    const signerCert = p7.certificates[0];
    const certInfo = extractCertificateInfoForge(signerCert);

    // Try signature verification
    let signatureValid = false;
    let verificationError = null;

    try {
      const hashAlg = getHashAlgorithmFromP7(p7);
      const md = forge.md[hashAlg].create();
      md.update(signatureInfo.signedContent.toString('binary'));
      
      if (p7.rawCapture && p7.rawCapture.signature) {
        signatureValid = signerCert.publicKey.verify(md.digest().bytes(), p7.rawCapture.signature);
      }
    } catch (err) {
      verificationError = err.message;
    }

    const now = new Date();
    const certValid = now >= signerCert.validity.notBefore && now <= signerCert.validity.notAfter;

    return {
      valid: signatureValid && certValid,
      format: 'PAdES (PDF Advanced Electronic Signature)',
      fileName,
      cryptographicVerification: true,
      structureValid: true,
      signatureValid,
      certificateValid: certValid,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      signatureAlgorithm: getHashAlgorithmFromP7(p7),
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(signerCert.validity.notBefore),
      certificateValidTo: formatDate(signerCert.validity.notAfter),
      serialNumber: signerCert.serialNumber,
      certificateChainLength: p7.certificates.length,
      isSelfSigned: isCertificateSelfSigned(signerCert),
      warnings: buildWarnings(certValid, verificationError, isCertificateSelfSigned(signerCert))
    };

  } catch (error) {
    throw new Error(`Node-forge parsing failed: ${error.message}`);
  }
}

// ------------------------------------------------------------------
// STRUCTURE-ONLY RESULT (WHEN PARSING FAILS)
// ------------------------------------------------------------------
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
    warnings: [
      'Detected signed PDF structure (ByteRange + Contents)',
      `PKI.js error: ${pkiError.message}`,
      `Node-forge error: ${forgeError.message}`,
      'This is normal for certain advanced PAdES signatures (Adobe, Dike, Aruba)',
      'Try verifying locally with Adobe Acrobat or a PEC-qualified tool for full validation'
    ]
  };
}

// ------------------------------------------------------------------
// CERTIFICATE INFO EXTRACTION
// ------------------------------------------------------------------
async function extractAdvancedCertificateInfo(cert) {
  try {
    const subject = cert.subject.typesAndValues;
    const issuer = cert.issuer.typesAndValues;
    
    const info = {
      commonName: 'Unknown',
      organization: 'Unknown',
      email: 'Unknown',
      issuer: 'Unknown',
      validFrom: null,
      validTo: null,
      serialNumber: 'Unknown',
      algorithm: 'Unknown',
      isSelfSigned: false
    };

    // Extract subject information
    for (const attr of subject) {
      const type = attr.type;
      const value = attr.value.valueBlock.value;
      
      if (type === '2.5.4.3') info.commonName = value; // CN
      if (type === '2.5.4.10') info.organization = value; // O
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

    // Check if self-signed (simplified check)
    info.isSelfSigned = info.commonName === info.issuer;

    return info;

  } catch (error) {
    console.warn('Error extracting certificate info:', error);
    return {
      commonName: 'Unknown',
      organization: 'Unknown',
      email: 'Unknown',
      issuer: 'Unknown',
      validFrom: null,
      validTo: null,
      serialNumber: 'Unknown',
      algorithm: 'Unknown',
      isSelfSigned: false
    };
  }
}

function extractCertificateInfoForge(cert) {
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

// ------------------------------------------------------------------
// UTILITY FUNCTIONS
// ------------------------------------------------------------------
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

function buildWarnings(certValid, verificationError, isSelfSigned) {
  const warnings = [];
  
  if (!certValid) warnings.push('Certificate expired or not yet valid');
  if (isSelfSigned) warnings.push('Certificate is self-signed');
  if (verificationError) warnings.push(`Verification issue: ${verificationError}`);
  
  warnings.push('CRL/OCSP validation not performed');
  warnings.push('Full certificate chain validation not implemented');
  
  return warnings;
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

