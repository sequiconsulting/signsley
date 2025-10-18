const forge = require('node-forge');

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

function extractCertificateInfo(cert) {
  const info = {
    commonName: 'Unknown',
    organization: 'Unknown',
    email: 'Unknown',
    issuer: 'Unknown',
    serialNumber: 'Unknown'
  };

  try {
    cert.subject.attributes.forEach(attr => {
      if (attr.shortName === 'CN') info.commonName = attr.value;
      if (attr.shortName === 'O') info.organization = attr.value;
      if (attr.shortName === 'emailAddress') info.email = attr.value;
    });

    cert.issuer.attributes.forEach(attr => {
      if (attr.shortName === 'CN') info.issuer = attr.value;
    });
    
    info.serialNumber = cert.serialNumber;
  } catch (e) {}

  return info;
}

function getCertificateDetails(cert, index) {
  try {
    const subject = cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
    const issuer = cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
    
    return {
      position: index + 1,
      subject: subject,
      issuer: issuer,
      serialNumber: cert.serialNumber,
      validFrom: formatDate(cert.validity.notBefore),
      validTo: formatDate(cert.validity.notAfter),
      isSelfSigned: cert.issuer.hash === cert.subject.hash,
      publicKeyAlgorithm: 'RSA',
      keySize: cert.publicKey.n ? cert.publicKey.n.bitLength() : 'Unknown'
    };
  } catch (e) {
    return null;
  }
}

function buildCertificateChain(p7) {
  const chain = [];
  
  if (p7.certificates && p7.certificates.length > 0) {
    p7.certificates.forEach((cert, idx) => {
      const details = getCertificateDetails(cert, idx);
      if (details) {
        chain.push(details);
      }
    });
  }
  
  return chain;
}

function extractSigningTime(p7) {
  try {
    if (p7.rawCapture && p7.rawCapture.authenticatedAttributes) {
      for (let attr of p7.rawCapture.authenticatedAttributes) {
        const attrOid = forge.asn1.derToOid(attr.value[0].value);
        if (attrOid === forge.pki.oids.signingTime) {
          const timeValue = attr.value[1].value[0].value;
          return formatDate(new Date(timeValue));
        }
      }
    }
  } catch (e) {}
  return null;
}

// Enhanced signature detection with better PDF parsing
function extractAllHexContents(pdfString) {
  const allHex = [];
  
  // Method 1: Standard /Contents pattern
  const contentsPattern = /\/Contents\s*<([0-9a-fA-F\s\r\n]+)>/gi;
  let match;
  
  while ((match = contentsPattern.exec(pdfString)) !== null) {
    const hex = match[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 100) {
      allHex.push({
        hex: hex,
        position: match.index,
        method: 'contents_tag'
      });
    }
  }

  // Method 2: Find hex strings in signature dictionaries
  const sigDictPattern = /\/Type\s*\/Sig[^>]*>([^<]*)<([0-9a-fA-F\s\r\n]{100,}?)>/gi;
  while ((match = sigDictPattern.exec(pdfString)) !== null) {
    const hex = match[2].replace(/[\s\r\n]+/g, '');
    if (hex.length > 100) {
      allHex.push({
        hex: hex,
        position: match.index,
        method: 'sig_dict'
      });
    }
  }

  // Method 3: Find long hex strings near signature objects
  const longHexPattern = /<([0-9a-fA-F\s\r\n]{200,}?)>/g;
  while ((match = longHexPattern.exec(pdfString)) !== null) {
    const hex = match[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 200) {
      allHex.push({
        hex: hex,
        position: match.index,
        method: 'long_hex'
      });
    }
  }
  
  return allHex;
}

function findByteRanges(pdfString) {
  const ranges = [];
  const pattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  let match;
  
  while ((match = pattern.exec(pdfString)) !== null) {
    ranges.push({
      range: [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), parseInt(match[4])],
      position: match.index
    });
  }
  
  return ranges;
}

function findAllSignatures(buffer) {
  const pdfString = buffer.toString('latin1');
  const signatures = [];
  const processed = new Set();
  
  // Enhanced signature detection
  const byteRanges = findByteRanges(pdfString);
  const hexContents = extractAllHexContents(pdfString);
  
  console.log(`Found ${byteRanges.length} ByteRange(s) and ${hexContents.length} hex Contents`);
  
  // Method 1: ByteRange matching with proximity search
  for (const range of byteRanges) {
    let closestHex = null;
    let minDistance = Infinity;
    
    for (const hexContent of hexContents) {
      const distance = Math.abs(hexContent.position - range.position);
      if (distance < minDistance && distance < 50000) { // Increased search window
        minDistance = distance;
        closestHex = hexContent;
      }
    }
    
    if (closestHex) {
      const key = closestHex.hex.substring(0, 100);
      if (!processed.has(key)) {
        processed.add(key);
        signatures.push({
          byteRange: range.range,
          signatureHex: closestHex.hex,
          method: `byterange_proximity_${closestHex.method}`
        });
      }
    }
  }
  
  // Method 2: Direct hex content analysis with PKCS#7 validation
  for (const hexContent of hexContents) {
    const key = hexContent.hex.substring(0, 100);
    if (!processed.has(key)) {
      // Enhanced PKCS#7 signature detection
      if (isPotentialPKCS7Signature(hexContent.hex)) {
        processed.add(key);
        signatures.push({
          byteRange: null,
          signatureHex: hexContent.hex,
          method: `hex_analysis_${hexContent.method}`
        });
      }
    }
  }
  
  // Method 3: Binary scan for PKCS#7 structures with context
  const hex = buffer.toString('hex');
  const pkcs7Patterns = [
    /3082[\da-f]{4}06092a864886f70d010702/gi, // Standard PKCS#7
    /3080[\da-f]{2,6}06092a864886f70d010702/gi, // Indefinite length
    /3082[\da-f]{4}06092a864886f70d010701/gi, // Data content type
  ];
  
  for (const pattern of pkcs7Patterns) {
    let match;
    while ((match = pattern.exec(hex)) !== null) {
      const startPos = match.index;
      const maxLen = Math.min(hex.length - startPos, 200000); // Increased buffer
      const sigHex = hex.substring(startPos, startPos + maxLen);
      
      const key = sigHex.substring(0, 100);
      if (!processed.has(key)) {
        processed.add(key);
        signatures.push({
          byteRange: null,
          signatureHex: sigHex,
          method: 'pkcs7_binary_scan'
        });
      }
    }
  }
  
  console.log(`Total unique signature candidates: ${signatures.length}`);
  return signatures;
}

// Enhanced PKCS#7 signature validation
function isPotentialPKCS7Signature(hex) {
  if (hex.length < 100) return false;
  
  // Check for PKCS#7 signature indicators
  const indicators = [
    '3082', // SEQUENCE with definite length
    '3080', // SEQUENCE with indefinite length
    '06092a864886f70d010702', // PKCS#7 signedData OID
    '06092a864886f70d010701', // PKCS#7 data OID
  ];
  
  return indicators.some(indicator => hex.toLowerCase().includes(indicator.toLowerCase()));
}

// Enhanced signature parsing with multiple recovery strategies
function tryParseSignature(signatureHex) {
  const strategies = [
    // Strategy 1: Direct parsing
    () => parseDirectly(signatureHex),
    
    // Strategy 2: Try different truncation points
    () => {
      for (let i = signatureHex.length; i >= 1000; i -= 1000) {
        try {
          const result = parseDirectly(signatureHex.substring(0, i));
          if (result) return result;
        } catch (e) {}
      }
      return null;
    },
    
    // Strategy 3: Find and parse embedded PKCS#7
    () => {
      const pkcs7Start = signatureHex.toLowerCase().indexOf('3082');
      if (pkcs7Start >= 0) {
        try {
          return parseDirectly(signatureHex.substring(pkcs7Start));
        } catch (e) {}
      }
      return null;
    },
    
    // Strategy 4: Try to fix common ASN.1 issues
    () => {
      try {
        // Remove potential padding or trailing data
        let cleaned = signatureHex.replace(/^00+/, ''); // Remove leading zeros
        cleaned = cleaned.replace(/00+$/, ''); // Remove trailing zeros
        return parseDirectly(cleaned);
      } catch (e) {
        return null;
      }
    },
    
    // Strategy 5: Parse as CMS/PKCS#7 with relaxed validation
    () => {
      try {
        return parseWithRelaxedValidation(signatureHex);
      } catch (e) {
        return null;
      }
    }
  ];
  
  for (const strategy of strategies) {
    try {
      const result = strategy();
      if (result && result.certificates && result.certificates.length > 0) {
        console.log('Successfully parsed with strategy');
        return result;
      }
    } catch (e) {
      console.log('Strategy failed:', e.message);
    }
  }
  
  return null;
}

function parseDirectly(signatureHex) {
  const bytes = Buffer.from(signatureHex, 'hex');
  const der = forge.util.createBuffer(bytes.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function parseWithRelaxedValidation(signatureHex) {
  // Try parsing with different ASN.1 strictness levels
  const bytes = Buffer.from(signatureHex, 'hex');
  const der = forge.util.createBuffer(bytes.toString('binary'));
  
  try {
    // First try strict parsing
    const asn1 = forge.asn1.fromDer(der);
    return forge.pkcs7.messageFromAsn1(asn1);
  } catch (e) {
    // Try with relaxed parsing - manually extract certificates
    try {
      return extractCertificatesManually(bytes);
    } catch (e2) {
      throw e; // Throw original error
    }
  }
}

function extractCertificatesManually(bytes) {
  // Manual certificate extraction for problematic signatures
  const certs = [];
  const hex = bytes.toString('hex');
  
  // Look for certificate patterns (X.509 certificates start with 3082)
  const certPattern = /3082[\da-f]{4}3082[\da-f]{4}/gi;
  let match;
  
  while ((match = certPattern.exec(hex)) !== null) {
    try {
      const startPos = match.index;
      // Try different lengths for the certificate
      for (let len = 2000; len <= 4000; len += 200) {
        try {
          const certHex = hex.substring(startPos, startPos + len);
          const certBytes = Buffer.from(certHex, 'hex');
          const certDer = forge.util.createBuffer(certBytes.toString('binary'));
          const certAsn1 = forge.asn1.fromDer(certDer);
          const cert = forge.pki.certificateFromAsn1(certAsn1);
          
          if (cert && cert.subject) {
            certs.push(cert);
            break;
          }
        } catch (e) {
          // Try next length
        }
      }
    } catch (e) {
      // Continue to next match
    }
  }
  
  if (certs.length > 0) {
    return {
      certificates: certs,
      rawCapture: {
        signature: null, // We couldn't parse the signature part
        content: null
      }
    };
  }
  
  throw new Error('No certificates found in manual extraction');
}

function getHashAlgorithmFromDigestOid(p7) {
  try {
    const oidBuffer = p7.rawCapture.digestAlgorithm;
    if (!oidBuffer) return 'sha256';

    const oidStr = forge.asn1.derToOid(oidBuffer);

    if (oidStr === forge.pki.oids.sha1 || oidStr.includes('1.3.14.3.2.26')) {
      return 'sha1';
    } else if (oidStr === forge.pki.oids.sha256 || oidStr.includes('2.16.840.1.101.3.4.2.1')) {
      return 'sha256';
    } else if (oidStr === forge.pki.oids.sha384 || oidStr.includes('2.16.840.1.101.3.4.2.2')) {
      return 'sha384';
    } else if (oidStr === forge.pki.oids.sha512 || oidStr.includes('2.16.840.1.101.3.4.2.3')) {
      return 'sha512';
    }

    return 'sha256';
  } catch (e) {
    return 'sha256';
  }
}

function verifySignatureCryptographically(p7) {
  let signatureValid = false;
  let verificationError = null;

  try {
    const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
    const attrs = p7.rawCapture.authenticatedAttributes;

    if (!p7.rawCapture || !p7.rawCapture.signature) {
      // If we couldn't parse the signature but have certificates, it's still a valid structure
      if (p7.certificates && p7.certificates.length > 0) {
        return { valid: false, error: 'Signature structure valid, cryptographic verification not possible' };
      }
      return { valid: false, error: 'No signature data found' };
    }

    if (!p7.certificates || p7.certificates.length === 0) {
      return { valid: false, error: 'No certificates found' };
    }

    const signerCert = p7.certificates[0];

    if (attrs) {
      const set = forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SET,
        true,
        attrs
      );

      const attrDer = forge.asn1.toDer(set);
      const md = forge.md[hashAlgorithm].create();
      md.update(attrDer.data);

      const signature = p7.rawCapture.signature;
      const publicKey = signerCert.publicKey;

      try {
        signatureValid = publicKey.verify(md.digest().bytes(), signature);
      } catch (verifyErr) {
        console.error('Signature verification failed:', verifyErr);
        verificationError = 'Signature verification failed';
        signatureValid = false;
      }

      if (signatureValid && p7.rawCapture.content) {
        let contentDigestValid = false;
        const contentMd = forge.md[hashAlgorithm].create();
        contentMd.update(p7.rawCapture.content);
        const contentDigest = contentMd.digest().bytes();

        for (let attr of attrs) {
          try {
            const attrOid = forge.asn1.derToOid(attr.value[0].value);
            if (attrOid === forge.pki.oids.messageDigest) {
              const attrDigest = attr.value[1].value[0].value;
              contentDigestValid = (attrDigest === contentDigest);
              break;
            }
          } catch (e) {
            continue;
          }
        }

        signatureValid = signatureValid && contentDigestValid;

        if (!contentDigestValid) {
          verificationError = 'Content digest mismatch';
        }
      }

    } else {
      if (p7.rawCapture.content) {
        const md = forge.md[hashAlgorithm].create();
        md.update(p7.rawCapture.content);

        const signature = p7.rawCapture.signature;
        try {
          signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
        } catch (verifyErr) {
          console.error('Signature verification failed:', verifyErr);
          verificationError = 'Signature verification failed';
          signatureValid = false;
        }
      } else {
        verificationError = 'No content to verify';
        signatureValid = false;
      }
    }

  } catch (e) {
    verificationError = e.message;
    signatureValid = false;
  }

  return { valid: signatureValid, error: verificationError };
}

function extractSignatureInfo(signatureHex) {
  try {
    const p7 = tryParseSignature(signatureHex);

    if (!p7 || !p7.certificates || p7.certificates.length === 0) {
      return null;
    }

    const cert = p7.certificates[0];
    const certInfo = extractCertificateInfo(cert);

    const now = new Date();
    const certValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;

    const verificationResult = verifySignatureCryptographically(p7);
    const signatureValid = verificationResult.valid;

    const signingTime = extractSigningTime(p7);
    const certificateChain = buildCertificateChain(p7);

    const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
    const signatureAlgorithm = `RSA-${hashAlgorithm.toUpperCase()}`;

    return {
      valid: signatureValid && certValid,
      certificateValid: certValid,
      signatureValid: signatureValid,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(cert.validity.notBefore),
      certificateValidTo: formatDate(cert.validity.notAfter),
      serialNumber: certInfo.serialNumber,
      isSelfSigned: cert.issuer.hash === cert.subject.hash,
      signatureDate: signingTime,
      certificateChain: certificateChain,
      certificateChainLength: p7.certificates.length,
      signatureAlgorithm: signatureAlgorithm,
      verificationError: verificationResult.error,
      structureOnly: !p7.rawCapture || !p7.rawCapture.signature
    };
  } catch (error) {
    console.error('Signature parsing error:', error);
    return null;
  }
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed', valid: false })
    };
  }

  const startTime = Date.now();

  try {
    const body = JSON.parse(event.body);
    const { fileData, fileName } = body;

    if (!fileData) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'No file data provided', valid: false })
      };
    }

    const estimatedSize = (fileData.length * 3) / 4;
    if (estimatedSize > 6 * 1024 * 1024) {
      return {
        statusCode: 413,
        headers,
        body: JSON.stringify({ 
          error: 'File too large',
          message: 'File must be under 6MB',
          valid: false
        })
      };
    }

    const buffer = Buffer.from(fileData, 'base64');
    const pdfString = buffer.toString('latin1');

    if (!pdfString.startsWith('%PDF-')) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Not a valid PDF file', valid: false })
      };
    }

    console.log(`Processing ${fileName} (${buffer.length} bytes)`);

    const signatures = findAllSignatures(buffer);

    if (signatures.length === 0) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          valid: false,
          format: 'PAdES (PDF Advanced Electronic Signature)',
          fileName,
          structureValid: false,
          error: 'No digital signature detected',
          warnings: [
            'No signature structures found',
            'PDF may not contain a digital signature'
          ],
          troubleshooting: [
            'Verify the PDF contains a digital signature',
            'Check if the file was properly signed',
            'Try opening in Adobe Acrobat Reader'
          ],
          processingTime: Date.now() - startTime
        })
      };
    }

    let sigInfo = null;
    let workingSig = null;
    let parseAttempts = [];
    
    for (const sig of signatures) {
      console.log(`Trying signature (method: ${sig.method}, hex length: ${sig.signatureHex.length})`);
      
      const info = extractSignatureInfo(sig.signatureHex);
      
      if (info) {
        sigInfo = info;
        workingSig = sig;
        console.log(`Successfully parsed signature using ${sig.method}`);
        break;
      } else {
        parseAttempts.push(sig.method);
      }
    }
    
    if (!sigInfo) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          valid: false,
          format: 'PAdES (PDF Advanced Electronic Signature)',
          fileName,
          structureValid: true,
          cryptographicVerification: false,
          error: 'Advanced signature encoding detected',
          warnings: [
            `Found ${signatures.length} signature structure(s)`,
            'Signature uses advanced or proprietary encoding',
            'Certificate information cannot be extracted'
          ],
          troubleshooting: [
            'Use Adobe Acrobat Reader for full verification',
            'Contact document signer for signature details',
            'Check if signature uses non-standard encoding',
            `Attempted parsing methods: ${parseAttempts.join(', ')}`
          ],
          processingTime: Date.now() - startTime
        })
      };
    }

    // Determine verification type based on available data
    const isStructureOnly = sigInfo.structureOnly || !sigInfo.signatureValid;
    
    const result = {
      valid: sigInfo.valid,
      format: 'PAdES (PDF Advanced Electronic Signature)',
      fileName,
      structureValid: true,
      cryptographicVerification: !isStructureOnly,
      signatureValid: sigInfo.signatureValid,
      certificateValid: sigInfo.certificateValid,
      signedBy: sigInfo.signedBy,
      organization: sigInfo.organization,
      email: sigInfo.email,
      certificateIssuer: sigInfo.certificateIssuer,
      certificateValidFrom: sigInfo.certificateValidFrom,
      certificateValidTo: sigInfo.certificateValidTo,
      serialNumber: sigInfo.serialNumber,
      isSelfSigned: sigInfo.isSelfSigned,
      signatureDate: sigInfo.signatureDate,
      certificateChainLength: sigInfo.certificateChainLength,
      signatureAlgorithm: sigInfo.signatureAlgorithm,
      detectionMethod: workingSig.method,
      certificateChain: sigInfo.certificateChain,
      warnings: [],
      troubleshooting: [],
      processingTime: Date.now() - startTime
    };

    // Add warnings based on findings
    if (signatures.length > 1) {
      result.warnings.push(`Multiple signatures detected (${signatures.length})`);
    }

    if (isStructureOnly) {
      result.warnings.push('Structure-only verification performed');
      result.troubleshooting.push('Use Adobe Acrobat Reader for cryptographic verification');
    }

    if (sigInfo.isSelfSigned) {
      result.warnings.push('Self-signed certificate detected');
    }

    if (!sigInfo.certificateValid) {
      result.warnings.push('Certificate has expired');
    }

    if (sigInfo.verificationError && !isStructureOnly) {
      result.warnings.push(`Verification issue: ${sigInfo.verificationError}`);
    }

    if (pdfString.includes('/EmbeddedFile')) {
      result.warnings.push('Document contains embedded files');
    }

    // Add standard disclaimers
    result.warnings.push('Certificate chain validation not performed');
    result.warnings.push('Revocation status not checked');

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(result)
    };

  } catch (error) {
    console.error('Handler error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Verification failed',
        message: error.message,
        valid: false,
        processingTime: Date.now() - startTime
      })
    };
  }
};

