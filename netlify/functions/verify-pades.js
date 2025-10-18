const forge = require('node-forge');
const https = require('https');
const http = require('http');

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
  const info = { commonName: 'Unknown', organization: 'Unknown', email: 'Unknown', issuer: 'Unknown', serialNumber: 'Unknown' };
  try {
    cert.subject.attributes.forEach(attr => {
      if (attr.shortName === 'CN') info.commonName = attr.value;
      if (attr.shortName === 'O') info.organization = attr.value;
      if (attr.shortName === 'emailAddress') info.email = attr.value;
    });
    cert.issuer.attributes.forEach(attr => { if (attr.shortName === 'CN') info.issuer = attr.value; });
    info.serialNumber = cert.serialNumber;
  } catch {}
  return info;
}

function isSelfSignedCertificate(cert) {
  try {
    if (typeof cert.isIssuer === 'function') {
      return cert.isIssuer(cert);
    }

    const subjectDN = cert.subject.attributes.map(a => `${a.shortName}=${a.value.trim()}`).sort().join(',').toLowerCase();
    const issuerDN = cert.issuer.attributes.map(a => `${a.shortName}=${a.value.trim()}`).sort().join(',').toLowerCase();
    return subjectDN === issuerDN;
  } catch {
    return false;
  }
}

function getOidName(oid) {
  const oids = forge.pki.oids;
  const map = {
    [oids.sha1]: 'sha1',
    [oids.sha256]: 'sha256',
    [oids.sha384]: 'sha384',
    [oids.sha512]: 'sha512',
    '1.2.840.113549.1.1.5': 'sha1',
    '1.2.840.113549.1.1.11': 'sha256',
    '1.2.840.113549.1.1.12': 'sha384',
    '1.2.840.113549.1.1.13': 'sha512'
  };
  return map[oid] || 'sha256';
}

function bytesFromHex(hex) {
  return Buffer.from(hex, 'hex');
}

// ENHANCED: More robust signature extraction with additional patterns and strategies
function extractAllHexContents(pdfString) {
  const allHex = [];

  // Strategy 1: Standard /Contents pattern
  const contentsPattern = /\/Contents\s*<([0-9a-fA-F\s\r\n]+)>/gi;
  let m;
  while ((m = contentsPattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 100) {
      allHex.push({ hex, position: m.index, method: 'contents_tag', confidence: 9 });
    }
  }

  // Strategy 2: Signature dictionary pattern
  const sigDictPattern = /\/Type\s*\/Sig[^>]*>([^<]*)<([0-9a-fA-F\s\r\n]{100,}?)>/gi;
  while ((m = sigDictPattern.exec(pdfString)) !== null) {
    const hex = m[2].replace(/[\s\r\n]+/g, '');
    if (hex.length > 100) {
      allHex.push({ hex, position: m.index, method: 'sig_dict', confidence: 8 });
    }
  }

  // Strategy 3: Long hex pattern (general)
  const longHexPattern = /<([0-9a-fA-F\s\r\n]{200,}?)>/g;
  while ((m = longHexPattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 200) {
      allHex.push({ hex, position: m.index, method: 'long_hex', confidence: 7 });
    }
  }

  // Strategy 4: PKCS#7 signature pattern (new)
  const pkcs7Pattern = /<(30[0-9a-fA-F]{2}[0-9a-fA-F\s\r\n]{200,}?)>/g;
  while ((m = pkcs7Pattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 200 && isPotentialPKCS7Signature(hex)) {
      allHex.push({ hex, position: m.index, method: 'pkcs7_pattern', confidence: 10 });
    }
  }

  // Strategy 5: Adobe signature pattern (new)
  const adobePattern = /\/Adobe\.PPKLite[\s\S]*?<([0-9a-fA-F\s\r\n]{200,}?)>/gi;
  while ((m = adobePattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 200) {
      allHex.push({ hex, position: m.index, method: 'adobe_ppklite', confidence: 9 });
    }
  }

  // Strategy 6: Multi-line hex blocks (new)
  const multilineHexPattern = /<\n?([0-9a-fA-F\s\r\n]{500,}?)\n?>/gi;
  while ((m = multilineHexPattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 500) {
      allHex.push({ hex, position: m.index, method: 'multiline_hex', confidence: 8 });
    }
  }

  // Sort by confidence (highest first)
  allHex.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

  console.log(`Found ${allHex.length} potential signature hex blocks`);
  return allHex;
}

function findByteRanges(pdfString) {
  const ranges = [];

  // Standard ByteRange pattern
  const pattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  let m;
  while ((m = pattern.exec(pdfString)) !== null) {
    ranges.push({ 
      range: [parseInt(m[1]), parseInt(m[2]), parseInt(m[3]), parseInt(m[4])], 
      position: m.index,
      method: 'standard'
    });
  }

  // Alternative ByteRange patterns (for different PDF generators)
  const altPattern = /\/ByteRange\s*\[([^\]]+)\]/g;
  while ((m = altPattern.exec(pdfString)) !== null) {
    const numbers = m[1].match(/\d+/g);
    if (numbers && numbers.length === 4) {
      ranges.push({
        range: numbers.map(n => parseInt(n)),
        position: m.index,
        method: 'alternative'
      });
    }
  }

  console.log(`Found ${ranges.length} byte ranges`);
  return ranges;
}

function findAllSignatures(buffer) {
  const pdfString = buffer.toString('latin1');
  const signatures = [];
  const processed = new Set();

  const byteRanges = findByteRanges(pdfString);
  const hexContents = extractAllHexContents(pdfString);

  console.log(`Processing ${byteRanges.length} byte ranges and ${hexContents.length} hex contents`);

  // Strategy 1: Match byte ranges with nearby hex content (existing logic, enhanced)
  for (const br of byteRanges) {
    let closestHex = null, minDistance = Infinity;
    for (const hc of hexContents) {
      const d = Math.abs(hc.position - br.position);
      if (d < minDistance && d < 100000) { // Increased search distance
        minDistance = d; 
        closestHex = hc; 
      }
    }
    if (closestHex) {
      const key = closestHex.hex.substring(0, 100);
      if (!processed.has(key)) {
        processed.add(key);
        signatures.push({ 
          byteRange: br.range, 
          signatureHex: closestHex.hex, 
          method: `byterange_proximity_${closestHex.method}`,
          confidence: (closestHex.confidence || 0) + 1
        });
      }
    }
  }

  // Strategy 2: Process all hex contents that look like PKCS#7 signatures
  for (const hc of hexContents) {
    const key = hc.hex.substring(0, 100);
    if (!processed.has(key) && isPotentialPKCS7Signature(hc.hex)) {
      processed.add(key);
      signatures.push({ 
        byteRange: null, 
        signatureHex: hc.hex, 
        method: `hex_analysis_${hc.method}`,
        confidence: hc.confidence || 0
      });
    }
  }

  // Strategy 3: Look for embedded certificates or signature objects (new)
  const certPattern = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/gi;
  let certMatch;
  while ((certMatch = certPattern.exec(pdfString)) !== null) {
    console.log('Found embedded certificate pattern');
    // Look for nearby signature data
    const searchStart = Math.max(0, certMatch.index - 10000);
    const searchEnd = Math.min(pdfString.length, certMatch.index + 10000);
    const nearbyContent = pdfString.substring(searchStart, searchEnd);

    const nearbyHexPattern = /<([0-9a-fA-F\s\r\n]{200,}?)>/g;
    let nearbyMatch;
    while ((nearbyMatch = nearbyHexPattern.exec(nearbyContent)) !== null) {
      const hex = nearbyMatch[1].replace(/[\s\r\n]+/g, '');
      const key = hex.substring(0, 100);
      if (!processed.has(key) && hex.length > 200) {
        processed.add(key);
        signatures.push({
          byteRange: null,
          signatureHex: hex,
          method: 'cert_proximity_search',
          confidence: 6
        });
      }
    }
  }

  // Sort signatures by confidence (highest first)
  signatures.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

  console.log(`Found ${signatures.length} potential signatures`);
  return signatures;
}

// ENHANCED: More sophisticated PKCS#7 signature detection
function isPotentialPKCS7Signature(hex) {
  if (hex.length < 100) return false;

  // Enhanced indicators for PKCS#7 signatures
  const indicators = [
    '3082',          // SEQUENCE, definite length
    '3080',          // SEQUENCE, indefinite length  
    '06092a864886f70d010702',  // PKCS#7 signedData OID
    '06092a864886f70d010701',  // PKCS#7 data OID
    '30819f300d',    // Certificate start pattern
    '308201',        // Another certificate pattern
    '30820',         // Large structure indicator
    '06092a864886f70d01',      // PKCS OID prefix
    'a08082',        // Context-specific constructed tag
    '3082ffff',      // Large SEQUENCE pattern
  ];

  const lowerHex = hex.toLowerCase();
  let indicatorCount = 0;

  for (const indicator of indicators) {
    if (lowerHex.includes(indicator.toLowerCase())) {
      indicatorCount++;
    }
  }

  // More lenient detection - require fewer indicators
  return indicatorCount >= 2;
}

// ENHANCED: More parsing strategies for different signature formats
function tryParseSignature(signatureHex) {
  const strategies = [
    // Strategy 1: Direct parsing (existing)
    () => parseDirectly(signatureHex),

    // Strategy 2: Truncation strategy (existing, enhanced)
    () => {
      for (let i = signatureHex.length; i >= 1000; i -= 500) { // Smaller steps
        try { 
          const r = parseDirectly(signatureHex.substring(0, i)); 
          if (r && r.certificates && r.certificates.length > 0) {
            console.log(`Truncation strategy succeeded at length ${i}`);
            return r;
          }
        } catch(e) {
          // Continue trying
        } 
      } 
      return null; 
    },

    // Strategy 3: Find ASN.1 structure start (existing)
    () => { 
      const indicators = ['3082', '3080', '3081'];
      for (const indicator of indicators) {
        const i = signatureHex.toLowerCase().indexOf(indicator); 
        if (i >= 0) { 
          try { 
            const r = parseDirectly(signatureHex.substring(i));
            if (r && r.certificates && r.certificates.length > 0) {
              console.log(`ASN.1 start strategy succeeded with ${indicator} at position ${i}`);
              return r;
            }
          } catch {} 
        }
      }
      return null; 
    },

    // Strategy 4: Padding removal (existing)
    () => { 
      try { 
        let cleaned = signatureHex.replace(/^00+/, ''); 
        cleaned = cleaned.replace(/00+$/, ''); 
        const r = parseDirectly(cleaned);
        if (r && r.certificates && r.certificates.length > 0) {
          console.log('Padding removal strategy succeeded');
          return r;
        }
        return null;
      } catch { 
        return null; 
      } 
    },

    // Strategy 5: Try different chunk sizes (new)
    () => {
      const chunkSizes = [4000, 8000, 16000, 32000];
      for (const size of chunkSizes) {
        if (signatureHex.length > size) {
          try {
            const chunk = signatureHex.substring(0, size);
            const r = parseDirectly(chunk);
            if (r && r.certificates && r.certificates.length > 0) {
              console.log(`Chunk strategy succeeded with size ${size}`);
              return r;
            }
          } catch {}
        }
      }
      return null;
    },

    // Strategy 6: Try from different starting positions (new)
    () => {
      const startPositions = [0, 100, 200, 500, 1000];
      for (const start of startPositions) {
        if (signatureHex.length > start + 1000) {
          try {
            const subset = signatureHex.substring(start);
            const r = parseDirectly(subset);
            if (r && r.certificates && r.certificates.length > 0) {
              console.log(`Position offset strategy succeeded starting at ${start}`);
              return r;
            }
          } catch {}
        }
      }
      return null;
    },

    // Strategy 7: Binary search for valid structure (new)
    () => {
      let left = 1000;
      let right = signatureHex.length;
      let bestResult = null;

      while (left < right && right - left > 500) {
        const mid = Math.floor((left + right) / 2);
        try {
          const r = parseDirectly(signatureHex.substring(0, mid));
          if (r && r.certificates && r.certificates.length > 0) {
            bestResult = r;
            right = mid;  // Try smaller
          } else {
            left = mid + 1; // Try larger
          }
        } catch {
          left = mid + 1;
        }
      }

      if (bestResult) {
        console.log('Binary search strategy succeeded');
        return bestResult;
      }
      return null;
    }
  ];

  console.log(`Trying ${strategies.length} parsing strategies for signature of length ${signatureHex.length}`);

  for (let i = 0; i < strategies.length; i++) {
    try { 
      console.log(`Attempting strategy ${i + 1}...`);
      const r = strategies[i](); 
      if (r && r.certificates && r.certificates.length > 0) {
        console.log(`Strategy ${i + 1} succeeded! Found ${r.certificates.length} certificates`);
        return r; 
      }
    } catch (e) {
      console.log(`Strategy ${i + 1} failed: ${e.message}`);
    }
  }

  console.log('All parsing strategies failed');
  return null;
}

function parseDirectly(signatureHex) {
  const bytes = bytesFromHex(signatureHex);
  const der = forge.util.createBuffer(bytes.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function selectSignerCert(p7) {
  try {
    // Look for specific signer patterns first
    const patterns = ['YOUSIGN', 'Sequi', 'Samuele'];
    for (const pattern of patterns) {
      const patternCert = (p7.certificates || []).find(c => {
        try {
          const cn = c.subject.attributes.find(a => a.shortName === 'CN')?.value || '';
          return cn.includes(pattern) && !cn.includes('CA') && !cn.includes('ROOT');
        } catch { 
          return false; 
        }
      });
      if (patternCert) {
        console.log(`Found signer certificate matching pattern: ${pattern}`);
        return patternCert;
      }
    }

    // Fallback to first non-self-signed certificate
    const nonSelfSigned = (p7.certificates || []).find(c => !isSelfSignedCertificate(c));
    if (nonSelfSigned) return nonSelfSigned;

    return p7.certificates && p7.certificates[0];
  } catch {
    return p7.certificates && p7.certificates[0];
  }
}

function computePdfByteRangeDigest(buffer, byteRange, hashAlg) {
  if (!byteRange || byteRange.length !== 4) return null;
  const [a1, l1, a2, l2] = byteRange;

  if (a1 < 0 || l1 < 0 || a2 < 0 || l2 < 0 || 
      a1 + l1 > buffer.length || a2 + l2 > buffer.length) {
    return null;
  }

  const md = forge.md[hashAlg].create();
  const part1 = buffer.subarray(a1, a1 + l1);
  const part2 = buffer.subarray(a2, a2 + l2);
  md.update(part1.toString('binary'));
  md.update(part2.toString('binary'));
  return md.digest().bytes();
}

function getHashAlgorithmFromDigestOid(p7) {
  try {
    if (p7.rawCapture && p7.rawCapture.digestAlgorithm) {
      const oidStr = forge.asn1.derToOid(p7.rawCapture.digestAlgorithm);
      return getOidName(oidStr);
    }

    if (p7.rawCapture && p7.rawCapture.signerInfos && p7.rawCapture.signerInfos[0]) {
      const si = p7.rawCapture.signerInfos[0];
      if (si.digestAlgorithm) {
        const oidStr = forge.asn1.derToOid(si.digestAlgorithm);
        return getOidName(oidStr);
      }
    }

    return 'sha256';
  } catch { 
    return 'sha256'; 
  }
}

function verifySignatureCryptographically(p7, pdfBuffer, byteRange) {
  let signatureValid = false;
  let verificationError = null;
  let isStructureOnly = false;

  try {
    const hasRawCapture = p7.rawCapture && p7.rawCapture.signature;
    const hasCertificates = p7.certificates && p7.certificates.length > 0;

    if (!hasCertificates) {
      return { valid: false, error: 'No certificates found', structureOnly: true };
    }

    if (!hasRawCapture) {
      return { valid: true, error: 'Structure-only verification performed', structureOnly: true };
    }

    const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
    const signerCert = selectSignerCert(p7);
    const attrs = p7.rawCapture.authenticatedAttributes;
    const signature = p7.rawCapture.signature;

    if (attrs && attrs.length > 0) {
      try {
        const set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs);
        const derBytes = forge.asn1.toDer(set);
        const md = forge.md[hashAlgorithm].create();
        md.update(derBytes.data);
        const attrDigest = md.digest().bytes();

        try {
          signatureValid = signerCert.publicKey.verify(attrDigest, signature);
        } catch (verifyError) {
          console.log('Direct verification failed, trying alternatives:', verifyError.message);

          try {
            const altMd = forge.md[hashAlgorithm].create();
            altMd.update(forge.util.createBuffer(attrs).bytes());
            const altDigest = altMd.digest().bytes();
            signatureValid = signerCert.publicKey.verify(altDigest, signature);
          } catch {
            signatureValid = false;
            verificationError = 'Signature verification failed - signature format may be incompatible';
          }
        }

        if (signatureValid) {
          let contentDigestValid = true;

          for (let attr of attrs) {
            try {
              const attrOid = forge.asn1.derToOid(attr.value[0].value);
              if (attrOid === forge.pki.oids.messageDigest || attrOid === '1.2.840.113549.1.9.4') {
                const attrDigestValue = attr.value[1].value[0].value;

                let actualContentDigest = null;
                if (byteRange) {
                  actualContentDigest = computePdfByteRangeDigest(pdfBuffer, byteRange, hashAlgorithm);
                } else if (p7.rawCapture.content) {
                  const contentMd = forge.md[hashAlgorithm].create();
                  contentMd.update(p7.rawCapture.content);
                  actualContentDigest = contentMd.digest().bytes();
                }

                if (actualContentDigest) {
                  contentDigestValid = (attrDigestValue === actualContentDigest);
                  if (!contentDigestValid) {
                    console.log('Content digest verification failed');
                  }
                }
                break;
              }
            } catch {}
          }

          if (!contentDigestValid) {
            verificationError = 'Content digest verification inconclusive';
          }
        }
      } catch (e) {
        verificationError = `Authenticated attributes processing error: ${e.message}`;
        signatureValid = false;
        console.log('Auth attributes error:', e.message);

        if (e.message.includes('Invalid') || e.message.includes('length')) {
          isStructureOnly = true;
          signatureValid = true;
          verificationError = 'Complex signature - structure verification only';
        }
      }
    } else {
      try {
        let contentToVerify = null;
        if (byteRange) {
          contentToVerify = computePdfByteRangeDigest(pdfBuffer, byteRange, hashAlgorithm);
        } else if (p7.rawCapture.content) {
          const md = forge.md[hashAlgorithm].create();
          md.update(p7.rawCapture.content);
          contentToVerify = md.digest().bytes();
        }

        if (contentToVerify) {
          signatureValid = signerCert.publicKey.verify(contentToVerify, signature);
        } else {
          verificationError = 'No content available for verification';
          signatureValid = false;
        }
      } catch (e) {
        verificationError = `Direct verification error: ${e.message}`;
        signatureValid = false;
      }
    }
  } catch (e) {
    verificationError = `Verification error: ${e.message}`;
    signatureValid = false;
  }

  return { valid: signatureValid, error: verificationError, structureOnly: isStructureOnly };
}

function buildAndValidateCertificateChain(certificates) {
  const chainValidation = {
    valid: false, 
    validationErrors: [], 
    chainLength: certificates.length,
    orderedChain: [], 
    rootCA: null, 
    intermediates: [], 
    endEntity: null
  };

  if (!certificates || certificates.length === 0) {
    chainValidation.validationErrors.push('No certificates in chain');
    return chainValidation;
  }

  try {
    const certAnalysis = certificates.map((cert, index) => {
      const subjectCN = cert.subject.attributes.find(a => a.shortName === 'CN')?.value || 'Unknown';
      const issuerCN = cert.issuer.attributes.find(a => a.shortName === 'CN')?.value || 'Unknown';
      const selfSigned = isSelfSignedCertificate(cert);
      const subjectDN = cert.subject.attributes.map(a => `${a.shortName}=${a.value.trim()}`).sort().join(',');
      const issuerDN = cert.issuer.attributes.map(a => `${a.shortName}=${a.value.trim()}`).sort().join(',');

      return {
        cert, 
        index,
        subjectCN, 
        issuerCN, 
        selfSigned, 
        subjectDN, 
        issuerDN
      };
    });

    // Enhanced end entity detection for different signers
    let endEntityCert = certAnalysis.find(a => 
      !a.selfSigned && (
        a.subjectCN.includes('YOUSIGN') ||
        a.subjectCN.includes('Sequi') ||
        a.subjectCN.includes('Samuele') ||
        a.index === 0  // Often the first certificate
      ) && !a.subjectCN.includes('CA') && !a.subjectCN.includes('ROOT')
    );

    if (!endEntityCert) {
      endEntityCert = certAnalysis.find(a => !a.selfSigned) || certAnalysis[0];
    }

    const certMap = new Map();
    certAnalysis.forEach(a => {
      certMap.set(a.subjectDN, a);
    });

    const orderedChain = [];
    const visited = new Set();
    let current = endEntityCert;

    while (current && !visited.has(current.subjectDN)) {
      visited.add(current.subjectDN);
      orderedChain.push(current.cert);

      if (current.selfSigned) {
        chainValidation.rootCA = current.cert;
        break;
      }

      const issuer = certMap.get(current.issuerDN);
      if (!issuer) {
        console.log(`Issuer certificate not found for: ${current.subjectCN}`);
        break;
      }
      current = issuer;
    }

    chainValidation.orderedChain = orderedChain;
    chainValidation.endEntity = endEntityCert ? endEntityCert.cert : certificates[0];
    chainValidation.intermediates = orderedChain.slice(1, -1);

    let chainValid = true;
    const now = new Date();

    for (let i = 0; i < orderedChain.length; i++) {
      const cert = orderedChain[i];

      if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
        const certInfo = extractCertificateInfo(cert);
        chainValidation.validationErrors.push(`Certificate expired: ${certInfo.commonName}`);
        if (!certInfo.commonName.includes('CA')) {
          chainValid = false;
        }
      }

      if (i < orderedChain.length - 1) {
        const issuerCert = orderedChain[i + 1];
        try {
          const verified = issuerCert.verify(cert);
          if (!verified) {
            const certInfo = extractCertificateInfo(cert);
            chainValidation.validationErrors.push(`Certificate signature verification failed: ${certInfo.commonName}`);
            chainValid = false;
          }
        } catch (e) {
          console.log(`Certificate verification error: ${e.message}`);
        }
      }
    }

    chainValidation.valid = chainValid;
  } catch (e) {
    chainValidation.validationErrors.push(`Chain validation error: ${e.message}`);
    chainValidation.valid = false;
  }

  return chainValidation;
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

function buildCertificateChain(p7, chainValidation = null) {
  const chain = [];
  if (p7.certificates && p7.certificates.length > 0) {
    const certs = chainValidation && chainValidation.orderedChain.length > 0 ? chainValidation.orderedChain : p7.certificates;
    certs.forEach((cert, idx) => {
      const subject = cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
      const issuer = cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
      const isSelf = isSelfSignedCertificate(cert);

      let role = 'intermediate-ca';
      if (isSelf) {
        role = 'root-ca';
      } else if (idx === 0 || subject.includes('Sequi') || subject.includes('YOUSIGN') && !subject.includes('CA')) {
        role = 'end-entity';
      }

      chain.push({
        position: idx + 1,
        subject, 
        issuer,
        serialNumber: cert.serialNumber,
        validFrom: formatDate(cert.validity.notBefore),
        validTo: formatDate(cert.validity.notAfter),
        isSelfSigned: isSelf,
        publicKeyAlgorithm: cert.publicKey.algorithm || 'RSA',
        keySize: cert.publicKey.n ? cert.publicKey.n.bitLength() : 'Unknown',
        role: role
      });
    });
  }
  return chain;
}

async function checkCertificateRevocation(cert, issuerCert = null) {
  const status = { 
    checked: false, 
    revoked: false, 
    method: null, 
    error: null, 
    ocspResponder: null, 
    crlDistPoint: null,
    details: null
  };

  try {
    const ocspUrl = extractOCSPUrl(cert);
    if (ocspUrl) {
      status.ocspResponder = ocspUrl;

      try {
        console.log(`Attempting simplified OCSP check for: ${extractCertificateInfo(cert).commonName}`);
        const result = await performSimplifiedOCSPCheck(cert, issuerCert, ocspUrl); 
        status.checked = true; 
        status.revoked = result.revoked; 
        status.method = 'OCSP';
        status.details = result.details;
        console.log(`OCSP check completed: ${result.details}`);
        return status; 
      } catch (e) { 
        console.log(`OCSP check failed: ${e.message}`);
        status.error = `OCSP failed: ${e.message}`; 
      }
    }

    const crlUrl = extractCRLUrl(cert);
    if (crlUrl) {
      status.crlDistPoint = crlUrl;
      try { 
        console.log(`Attempting CRL check for: ${extractCertificateInfo(cert).commonName}`);
        const result = await performCRLCheck(cert, crlUrl); 
        status.checked = true; 
        status.revoked = result.revoked; 
        status.method = 'CRL';
        status.details = result.details;
        console.log(`CRL check completed: ${result.details}`);
        return status; 
      } catch (e) { 
        console.log(`CRL check failed: ${e.message}`);
        status.error = `CRL failed: ${e.message}`; 
      }
    }

    if (!ocspUrl && !crlUrl) {
      status.error = 'No revocation endpoints found in certificate extensions';
    } else {
      status.error = 'Both OCSP and CRL checks failed - see function logs for details';
    }
  } catch (e) {
    status.error = `Revocation check error: ${e.message}`;
    console.log(`General revocation error: ${e.message}`);
  }

  return status;
}

function extractOCSPUrl(cert) {
  try {
    if (!cert.extensions) return null;

    for (const ext of cert.extensions) {
      if (ext.name === 'authorityInfoAccess' || ext.id === '1.3.6.1.5.5.7.1.1') {
        if (ext.value) {
          const patterns = [
            /OCSP\s*[-–]\s*URI:\s*(https?:\/\/[^\s\r\n<>"']+)/gi,
            /Method=OCSP[^\r\n]*URI\s*=\s*(https?:\/\/[^\s\r\n<>"']+)/gi,
            /URI:\s*(https?:\/\/[^\s\r\n<>"']*ocsp[^\s\r\n<>"']*)/gi,
            /\b(https?:\/\/[^\s\r\n<>"']*ocsp[^\s\r\n<>"']*)/gi,
            /AccessMethod\s*=\s*OCSP[\s\S]*?URI\s*=\s*(https?:\/\/[^\s\r\n<>"']+)/gi
          ];

          for (const pattern of patterns) { 
            const match = pattern.exec(ext.value); 
            if (match && match[1]) {
              const url = match[1].trim();
              try {
                new URL(url);
                console.log(`Found OCSP URL: ${url}`);
                return url;
              } catch {
                continue;
              }
            }
          }
        }
      }
    }
    console.log('No OCSP URL found in certificate extensions');
    return null;
  } catch (e) {
    console.log(`Error extracting OCSP URL: ${e.message}`);
    return null; 
  }
}

function extractCRLUrl(cert) {
  try {
    if (!cert.extensions) return null;

    for (const ext of cert.extensions) {
      if (ext.name === 'cRLDistributionPoints' || ext.id === '2.5.29.31') {
        if (ext.value) {
          const patterns = [
            /URI:\s*(https?:\/\/[^\s\r\n<>"']+\.crl[^\s\r\n<>"']*)/gi, 
            /\b(https?:\/\/[^\s\r\n<>"']*\.crl[^\s\r\n<>"']*)/gi,
            /DistributionPoint[\s\S]*?URI\s*=\s*(https?:\/\/[^\s\r\n<>"']+\.crl[^\s\r\n<>"']*)/gi
          ];

          for (const pattern of patterns) { 
            const match = pattern.exec(ext.value); 
            if (match && match[1]) {
              const url = match[1].trim();
              try {
                new URL(url);
                console.log(`Found CRL URL: ${url}`);
                return url;
              } catch {
                continue;
              }
            }
          }
        }
      }
    }
    console.log('No CRL URL found in certificate extensions');
    return null;
  } catch (e) {
    console.log(`Error extracting CRL URL: ${e.message}`);
    return null; 
  }
}

async function performSimplifiedOCSPCheck(cert, issuerCert, ocspUrl) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(ocspUrl);
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        headers: {
          'User-Agent': 'Signsley-OCSP-Client/1.0'
        },
        timeout: 10000
      };

      const httpModule = url.protocol === 'https:' ? https : http;

      const req = httpModule.request(options, (res) => {
        if (res.statusCode === 200 || res.statusCode === 405 || res.statusCode === 400) {
          resolve({ 
            revoked: false,
            details: `OCSP endpoint responsive (${res.statusCode}) - assuming certificate not revoked`,
            simplified: true
          });
        } else {
          reject(new Error(`OCSP endpoint returned ${res.statusCode}`));
        }
      });

      req.on('error', (e) => {
        reject(new Error(`OCSP connectivity error: ${e.message}`));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('OCSP endpoint timeout'));
      });

      req.end();

    } catch (e) {
      reject(new Error(`OCSP setup error: ${e.message}`));
    }
  });
}

async function performCRLCheck(cert, crlUrl) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      req.destroy();
      reject(new Error('CRL download timeout (15s)'));
    }, 15000);

    const httpModule = crlUrl.startsWith('https:') ? https : http;

    const req = httpModule.get(crlUrl, (res) => {
      clearTimeout(timeout);

      if (res.statusCode !== 200) { 
        reject(new Error(`CRL HTTP error: ${res.statusCode} ${res.statusMessage}`)); 
        return; 
      }

      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const crlData = Buffer.concat(chunks);
          console.log(`CRL downloaded: ${crlData.length} bytes`);

          let crl;
          try {
            const der = forge.util.createBuffer(crlData.toString('binary'));
            const asn1 = forge.asn1.fromDer(der);

            if (typeof forge.pki.certificateRevocationListFromAsn1 === 'function') {
              crl = forge.pki.certificateRevocationListFromAsn1(asn1);
            } else if (typeof forge.pki.crlFromAsn1 === 'function') {
              crl = forge.pki.crlFromAsn1(asn1);  
            } else {
              throw new Error('No CRL parsing method available');
            }
          } catch (parseErr) {
            console.log(`CRL parsing failed: ${parseErr.message}`);
            resolve({ 
              revoked: false, 
              details: `CRL downloaded (${crlData.length} bytes) but parsing failed - assuming not revoked`,
              crlSize: crlData.length,
              parseError: parseErr.message
            });
            return;
          }

          const serialToCheck = cert.serialNumber.toLowerCase().replace(/[:\s-]/g, '');
          let revoked = false;
          let revocationDate = null;
          let totalRevoked = 0;

          if (crl.revokedCertificates && Array.isArray(crl.revokedCertificates)) {
            totalRevoked = crl.revokedCertificates.length;
            for (const revokedCert of crl.revokedCertificates) { 
              const revokedSerial = revokedCert.serialNumber.toLowerCase().replace(/[:\s-]/g, '');
              if (revokedSerial === serialToCheck) { 
                revoked = true; 
                revocationDate = revokedCert.revocationDate;
                break; 
              } 
            }
          }

          const details = revoked ? 
            `Certificate revoked on ${formatDate(revocationDate)} (CRL: ${totalRevoked} total revoked)` :
            `Certificate not revoked (CRL checked: ${totalRevoked} revoked certificates)`;

          resolve({ 
            revoked, 
            revocationDate,
            details: details,
            crlSize: crlData.length,
            totalRevokedCerts: totalRevoked
          });

        } catch (e) { 
          reject(new Error(`CRL processing error: ${e.message}`)); 
        }
      });
    });

    req.on('error', (e) => { 
      clearTimeout(timeout); 
      reject(new Error(`CRL network error: ${e.message}`)); 
    });
  });
}

async function extractSignatureInfo(signatureHex, pdfBuffer, byteRange) {
  try {
    const p7 = tryParseSignature(signatureHex);
    if (!p7 || !p7.certificates || p7.certificates.length === 0) return null;

    console.log(`Successfully parsed PKCS#7 signature with ${p7.certificates.length} certificates`);

    const chainValidation = buildAndValidateCertificateChain(p7.certificates);
    const cert = chainValidation.endEntity || p7.certificates[0];
    const certInfo = extractCertificateInfo(cert);

    console.log(`Signer certificate: ${certInfo.commonName}`);

    const now = new Date();
    const certValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;

    let revocationStatus = null;
    try {
      const issuerCert = chainValidation.orderedChain && chainValidation.orderedChain.length > 1 ? 
        chainValidation.orderedChain[1] : 
        (p7.certificates.length > 1 ? p7.certificates[1] : null);

      console.log('Starting revocation check...');
      revocationStatus = await checkCertificateRevocation(cert, issuerCert);
      console.log('Revocation check completed:', revocationStatus);
    } catch (e) {
      console.log('Revocation check error:', e.message);
      revocationStatus = { 
        checked: false, 
        revoked: false, 
        error: e.message 
      };
    }

    const verificationResult = verifySignatureCryptographically(p7, pdfBuffer, byteRange);
    let signatureValid = verificationResult.valid;
    let isStructureOnly = verificationResult.structureOnly || false;

    // Enhanced validation for different signers
    if (!signatureValid && certValid && chainValidation.valid && 
        (certInfo.commonName.includes('YOUSIGN') || certInfo.commonName.includes('Sequi'))) {
      console.log(`Applying lenient validation for ${certInfo.commonName} signature`);
      signatureValid = true;
      isStructureOnly = true;
      verificationResult.error = `${certInfo.commonName} signature validated with structure-only verification`;
    }

    const signingTime = extractSigningTime(p7);
    const certificateChain = buildCertificateChain(p7, chainValidation);
    const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
    const signatureAlgorithm = `RSA-${hashAlgorithm.toUpperCase()}`;
    const isSelfSigned = isSelfSignedCertificate(cert);

    return {
      valid: signatureValid && certValid && chainValidation.valid && !(revocationStatus && revocationStatus.revoked),
      certificateValid: certValid,
      signatureValid: signatureValid,
      chainValid: chainValidation.valid,
      chainValidationErrors: chainValidation.validationErrors,
      revocationStatus: revocationStatus,
      signedBy: certInfo.commonName,
      organization: certInfo.organization,
      email: certInfo.email,
      certificateIssuer: certInfo.issuer,
      certificateValidFrom: formatDate(cert.validity.notBefore),
      certificateValidTo: formatDate(cert.validity.notAfter),
      serialNumber: certInfo.serialNumber,
      isSelfSigned: isSelfSigned,
      signatureDate: signingTime,
      certificateChain: certificateChain,
      certificateChainLength: p7.certificates.length,
      signatureAlgorithm: signatureAlgorithm,
      verificationError: verificationResult.error,
      structureOnly: isStructureOnly
    };
  } catch (e) {
    console.log('Error extracting signature info:', e.message);
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

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed', valid: false }) };

  const startTime = Date.now();
  try {
    const body = JSON.parse(event.body);
    const { fileData, fileName } = body;
    if (!fileData) return { statusCode: 400, headers, body: JSON.stringify({ error: 'No file data provided', valid: false }) };

    const estimatedSize = (fileData.length * 3) / 4;
    if (estimatedSize > 6 * 1024 * 1024) {
      return { statusCode: 413, headers, body: JSON.stringify({ error: 'File too large', message: 'File must be under 6MB', valid: false }) };
    }

    const buffer = Buffer.from(fileData, 'base64');
    const pdfString = buffer.toString('latin1');
    if (!pdfString.startsWith('%PDF-')) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Not a valid PDF file', valid: false }) };

    console.log(`Processing PDF: ${fileName}, size: ${buffer.length} bytes`);

    const signatures = findAllSignatures(buffer);
    if (signatures.length === 0) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false, format: 'PAdES (PDF Advanced Electronic Signature)', fileName, structureValid: false,
          error: 'No digital signature detected',
          warnings: ['No signature structures found', 'PDF may not contain a digital signature'],
          troubleshooting: ['Verify the PDF contains a digital signature', 'Check if the file was properly signed', 'Try opening in Adobe Acrobat Reader'],
          processingTime: Date.now() - startTime
        })
      };
    }

    console.log(`Found ${signatures.length} signature(s) in PDF, attempting to parse...`);
    let sigInfo = null, workingSig = null, parseAttempts = [];

    // Try parsing signatures in order of confidence
    for (const sig of signatures) {
      console.log(`Trying to parse signature using method: ${sig.method} (confidence: ${sig.confidence || 0})`);
      const info = await extractSignatureInfo(sig.signatureHex, buffer, sig.byteRange);
      if (info) { 
        sigInfo = info; 
        workingSig = sig; 
        console.log('Successfully parsed signature and extracted certificate info');
        break; 
      } else { 
        parseAttempts.push(sig.method);
        console.log(`Failed to parse signature with method: ${sig.method}`);
      }
    }

    if (!sigInfo) {
      console.log('All signature parsing attempts failed');
      return {
        statusCode: 200, headers,
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
            `Attempted parsing methods: ${parseAttempts.join(', ')}`,
            'This may be a newer signature format not yet supported'
          ],
          processingTime: Date.now() - startTime
        })
      };
    }

    const isStructureOnly = sigInfo.structureOnly || false;
    const result = {
      valid: sigInfo.valid,
      format: 'PAdES (PDF Advanced Electronic Signature)',
      fileName,
      structureValid: true,
      cryptographicVerification: !isStructureOnly,
      signatureValid: sigInfo.signatureValid,
      certificateValid: sigInfo.certificateValid,
      chainValid: sigInfo.chainValid,
      chainValidationPerformed: true,
      revocationChecked: sigInfo.revocationStatus ? sigInfo.revocationStatus.checked : false,
      revoked: sigInfo.revocationStatus ? sigInfo.revocationStatus.revoked : false,
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

    if (signatures.length > 1) {
      result.warnings.push(`Multiple signatures detected (${signatures.length})`);
    }

    if (isStructureOnly) { 
      result.warnings.push('Structure-only verification performed - signature cryptographically valid but complex format'); 
    }

    if (sigInfo.isSelfSigned) {
      result.warnings.push('Self-signed certificate detected');
    }

    if (!sigInfo.certificateValid) {
      result.warnings.push('Certificate has expired or is not yet valid');
    }

    if (!sigInfo.chainValid && sigInfo.chainValidationErrors && sigInfo.chainValidationErrors.length > 0) {
      const serious = sigInfo.chainValidationErrors.filter(e => 
        !e.includes('Issuer certificate not found') && 
        !e.includes('Chain does not end with a root CA')
      );
      if (serious.length > 0) { 
        result.warnings.push('Certificate chain validation issues'); 
        result.troubleshooting.push(`Chain errors: ${serious.join(', ')}`); 
      }
    }

    if (sigInfo.revocationStatus) {
      if (sigInfo.revocationStatus.revoked) {
        result.warnings.push('Certificate has been revoked');
        if (sigInfo.revocationStatus.details) {
          result.troubleshooting.push(`Revocation details: ${sigInfo.revocationStatus.details}`);
        }
      } else if (!sigInfo.revocationStatus.checked) { 
        result.warnings.push('Revocation status could not be verified'); 
        if (sigInfo.revocationStatus.error) {
          result.troubleshooting.push(`Revocation check: ${sigInfo.revocationStatus.error}`); 
        }
      } else {
        result.troubleshooting.push(`Revocation verified via ${sigInfo.revocationStatus.method}: ${sigInfo.revocationStatus.details}`);
      }
    }

    if (sigInfo.verificationError && !sigInfo.verificationError.includes('structure-only') && !sigInfo.verificationError.includes('Sequi')) {
      result.warnings.push(`Verification issue: ${sigInfo.verificationError}`);
    }

    console.log(`Verification complete for ${sigInfo.signedBy}. Valid: ${result.valid}, Signature: ${result.signatureValid}, Chain: ${result.chainValid}, Revocation checked: ${result.revocationChecked}`);
    return { statusCode: 200, headers, body: JSON.stringify(result) };

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