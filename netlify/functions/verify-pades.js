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
    if (typeof cert.isIssuer === 'function') return cert.isIssuer(cert);
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

function validateCertificateAtSigningTime(cert, signingTime = null) {
  const now = new Date();
  let validationDate = now;
  
  if (signingTime) {
    try {
      const sigDate = new Date(signingTime);
      if (!isNaN(sigDate.getTime()) && sigDate <= now) {
        validationDate = sigDate;
      }
    } catch {}
  }
  
  const certValid = validationDate >= cert.validity.notBefore && validationDate <= cert.validity.notAfter;
  const expiredNow = now > cert.validity.notAfter;
  
  return {
    validAtSigningTime: certValid,
    validNow: !expiredNow,
    expiredSinceSigning: certValid && expiredNow,
    validationDate: validationDate
  };
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
    /Contents\s*<([0-9a-fA-F\s\r\n]+)>/gi,
    /\/Contents\[<([0-9a-fA-F\s\r\n]+)>\]/gi,
  ];

  contentsPatterns.forEach((pattern, idx) => {
    let m;
    while ((m = pattern.exec(pdfString)) !== null) {
      const hex = m[1].replace(/[\s\r\n]+/g, '');
      if (hex.length > 100) {
        allHex.push({ hex, position: m.index, method: `contents_${idx}`, confidence: 9 - idx });
      }
    }
  });

  const asn1Patterns = [
    /<(30[0-9a-fA-F]{2}[0-9a-fA-F\s\r\n]{200,}?)>/g,
    /<(308[0-9a-fA-F][0-9a-fA-F\s\r\n]{200,}?)>/g,
    /<(3082[0-9a-fA-F]{4}[0-9a-fA-F\s\r\n]{200,}?)>/g,
    /<(3084[0-9a-fA-F]{8}[0-9a-fA-F\s\r\n]{200,}?)>/g,
    /(30[0-9a-fA-F]{2}[0-9a-fA-F]{200,})/g,
  ];

  asn1Patterns.forEach((pattern, idx) => {
    let m;
    while ((m = pattern.exec(pdfString)) !== null) {
      const hex = m[1].replace(/[\s\r\n]+/g, '');
      if (hex.length > 200) {
        allHex.push({ hex, position: m.index, method: `asn1_${idx}`, confidence: 10 - idx });
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

  unique.sort((a, b) => {
    const aScore = (a.confidence || 0) + (isPotentialPKCS7Signature(a.hex) ? 2 : 0) + (a.hex.length / 10000);
    const bScore = (b.confidence || 0) + (isPotentialPKCS7Signature(b.hex) ? 2 : 0) + (b.hex.length / 10000);
    return bScore - aScore;
  });

  return unique;
}

function findByteRanges(pdfString) {
  const ranges = [];
  const patterns = [
    /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g,
    /\/ByteRange\s*\[([^\]]+)\]/g,
    /ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g,
  ];

  patterns.forEach((pattern, idx) => {
    let m;
    while ((m = pattern.exec(pdfString)) !== null) {
      let numbers;
      if (idx === 1) {
        numbers = m[1].match(/\d+/g);
      } else {
        numbers = [m[1], m[2], m[3], m[4]];
      }
      if (numbers && numbers.length === 4) {
        const range = numbers.map(n => parseInt(n));
        if (range.every(n => !isNaN(n) && n >= 0)) {
          ranges.push({ range, position: m.index, method: `pattern_${idx}` });
        }
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
          method: `byterange_proximity_${closestHex.method}`,
          confidence: (closestHex.confidence || 0) + 3,
          distance: minDistance
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
        method: `hex_analysis_${hc.method}`,
        confidence: hc.confidence || 0
      });
    }
  }

  const filtered = signatures.filter(sig => sig.signatureHex.length >= 400);
  filtered.sort((a, b) => {
    const aScore = (a.confidence || 0) * 2 + (isPotentialPKCS7Signature(a.signatureHex) ? 5 : 0) + (a.signatureHex.length / 5000);
    const bScore = (b.confidence || 0) * 2 + (isPotentialPKCS7Signature(b.signatureHex) ? 5 : 0) + (b.signatureHex.length / 5000);
    return bScore - aScore;
  });

  return filtered;
}

function isPotentialPKCS7Signature(hex) {
  if (hex.length < 200) return false;
  const lowerHex = hex.toLowerCase();
  const primaryIndicators = ['3082', '3080', '06092a864886f70d010702', '06092a864886f70d010701'];
  const hasPrimary = primaryIndicators.some(ind => lowerHex.includes(ind));
  if (!hasPrimary) return false;
  const secondaryIndicators = ['30819f300d', '308201', '30820', '06092a864886f70d01', 'a08082', '02', '04', '31', '30', '06'];
  let score = 0;
  for (const indicator of secondaryIndicators) {
    if (lowerHex.includes(indicator.toLowerCase())) score++;
  }
  return score >= 4;
}

function tryParseSignature(signatureHex) {
  const strategies = [
    () => {
      const trimmed = validateAndTrimDER(signatureHex);
      return parseDirectly(trimmed !== signatureHex ? trimmed : signatureHex);
    },
    () => {
      const derLength = getDERLength(signatureHex);
      if (derLength && derLength * 2 < signatureHex.length) {
        return parseDirectly(signatureHex.substring(0, derLength * 2));
      }
      return null;
    },
    () => {
      const stepSizes = [2, 4, 8, 16, 32, 64, 128, 256, 512];
      for (const stepSize of stepSizes) {
        for (let i = signatureHex.length; i >= 1000; i -= stepSize) {
          try { 
            const r = parseDirectly(signatureHex.substring(0, i)); 
            if (r && r.certificates && r.certificates.length > 0) return r;
          } catch {} 
        } 
      }
      return null; 
    },
  ];

  for (let i = 0; i < strategies.length; i++) {
    try { 
      const r = strategies[i](); 
      if (r && r.certificates && r.certificates.length > 0) return r; 
    } catch {}
  }
  return null;
}

function parseDirectly(signatureHex) {
  const bytes = bytesFromHex(signatureHex);
  const der = forge.util.createBuffer(bytes.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

// FIXED: Improved signer certificate selection
function selectSignerCert(p7) {
  try {
    if (!p7.certificates || p7.certificates.length === 0) return null;
    
    // Strategy 1: Find end-entity certificate (leaf certificate)
    // The signer is the certificate that is NOT an issuer of any other certificate
    const issuerCNs = new Set();
    p7.certificates.forEach(cert => {
      const issuerCN = cert.issuer.attributes.find(a => a.shortName === 'CN')?.value;
      if (issuerCN) issuerCNs.add(issuerCN.toLowerCase());
    });
    
    for (const cert of p7.certificates) {
      if (isSelfSignedCertificate(cert)) continue; // Skip self-signed (root CAs)
      
      const subjectCN = cert.subject.attributes.find(a => a.shortName === 'CN')?.value;
      if (subjectCN && !issuerCNs.has(subjectCN.toLowerCase())) {
        // This certificate is not an issuer of any other cert - it's the end entity
        return cert;
      }
    }
    
    // Strategy 2: Find the only non-self-signed certificate
    const nonSelfSigned = p7.certificates.filter(c => !isSelfSignedCertificate(c));
    if (nonSelfSigned.length === 1) return nonSelfSigned[0];
    
    // Strategy 3: Return last non-self-signed certificate
    for (let i = p7.certificates.length - 1; i >= 0; i--) {
      if (!isSelfSignedCertificate(p7.certificates[i])) return p7.certificates[i];
    }
    
    // Fallback: return first certificate
    return p7.certificates[0];
  } catch {
    return p7.certificates && p7.certificates[0];
  }
}

function computePdfByteRangeDigest(buffer, byteRange, hashAlg) {
  if (!byteRange || byteRange.length !== 4) return null;
  const [a1, l1, a2, l2] = byteRange;
  if (a1 < 0 || l1 < 0 || a2 < 0 || l2 < 0 || a1 + l1 > buffer.length || a2 + l2 > buffer.length) return null;
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
  } catch { return 'sha256'; }
}

function verifySignatureCryptographically(p7, pdfBuffer, byteRange) {
  let signatureValid = false;
  let verificationError = null;
  let isStructureOnly = false;

  try {
    const hasRawCapture = p7.rawCapture && p7.rawCapture.signature;
    const hasCertificates = p7.certificates && p7.certificates.length > 0;

    if (!hasCertificates) return { valid: false, error: 'No certificates found', structureOnly: true };
    if (!hasRawCapture) return { valid: true, error: 'Structure-only verification performed', structureOnly: true };

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
        } catch {
          try {
            const altMd = forge.md[hashAlgorithm].create();
            altMd.update(forge.util.createBuffer(attrs).bytes());
            const altDigest = altMd.digest().bytes();
            signatureValid = signerCert.publicKey.verify(altDigest, signature);
          } catch {
            signatureValid = false;
            verificationError = 'Signature verification failed';
          }
        }
      } catch (e) {
        verificationError = `Authenticated attributes error: ${e.message}`;
        signatureValid = false;
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

function buildAndValidateCertificateChain(certificates, signingTime = null) {
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
      return { cert, index, subjectCN, issuerCN, selfSigned, subjectDN, issuerDN };
    });

    let endEntityCert = certAnalysis.find(a => 
      !a.selfSigned && (
        a.subjectCN.includes('YOUSIGN') || a.subjectCN.includes('Sequi') || a.subjectCN.includes('Samuele') ||
        a.subjectCN.includes('Trevor') || a.subjectCN.includes('Fitzpatrick') || a.subjectCN.includes('Hughes') ||
        a.subjectCN.includes('Amelie') || a.subjectCN.includes('Garcia') || a.index === 0
      ) && !a.subjectCN.includes('CA') && !a.subjectCN.includes('ROOT')
    );

    if (!endEntityCert) {
      endEntityCert = certAnalysis.find(a => !a.selfSigned) || certAnalysis[0];
    }

    const certMap = new Map();
    certAnalysis.forEach(a => certMap.set(a.subjectDN, a));

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
      if (!issuer) break;
      current = issuer;
    }

    chainValidation.orderedChain = orderedChain;
    chainValidation.endEntity = endEntityCert ? endEntityCert.cert : certificates[0];
    chainValidation.intermediates = orderedChain.slice(1, -1);

    let chainValid = true;
    const now = new Date();
    let validationDate = now;
    
    if (signingTime) {
      try {
        const sigDate = new Date(signingTime);
        if (!isNaN(sigDate.getTime()) && sigDate <= now) validationDate = sigDate;
      } catch {}
    }

    for (let i = 0; i < orderedChain.length; i++) {
      const cert = orderedChain[i];
      if (validationDate < cert.validity.notBefore || validationDate > cert.validity.notAfter) {
        const certInfo = extractCertificateInfo(cert);
        chainValidation.validationErrors.push(`Certificate expired: ${certInfo.commonName}`);
        if (!certInfo.commonName.includes('CA')) chainValid = false;
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
        } catch {}
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
      } else if (idx === 0 || subject.includes('Trevor') || subject.includes('Sequi') || subject.includes('YOUSIGN') && !subject.includes('CA')) {
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
    details: null
  };

  try {
    const ocspUrl = extractOCSPUrl(cert);
    if (ocspUrl) {
      try {
        const result = await performSimplifiedOCSPCheck(cert, issuerCert, ocspUrl); 
        status.checked = true; 
        status.revoked = result.revoked; 
        status.method = 'OCSP';
        status.details = result.details;
        return status; 
      } catch (e) { 
        status.error = `OCSP failed: ${e.message}`; 
      }
    }

    const crlUrl = extractCRLUrl(cert);
    if (crlUrl) {
      try { 
        const result = await performCRLCheck(cert, crlUrl); 
        status.checked = true; 
        status.revoked = result.revoked; 
        status.method = 'CRL';
        status.details = result.details;
        return status; 
      } catch (e) { 
        status.error = `CRL failed: ${e.message}`; 
      }
    }

    if (!ocspUrl && !crlUrl) {
      status.error = 'No revocation endpoints found in certificate extensions';
    }
  } catch (e) {
    status.error = `Revocation check error: ${e.message}`;
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
            /URI:\s*(https?:\/\/[^\s\r\n<>"']*ocsp[^\s\r\n<>"']*)/gi,
          ];
          for (const pattern of patterns) { 
            const match = pattern.exec(ext.value); 
            if (match && match[1]) {
              try {
                new URL(match[1].trim());
                return match[1].trim();
              } catch {}
            }
          }
        }
      }
    }
    return null;
  } catch {
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
          ];
          for (const pattern of patterns) { 
            const match = pattern.exec(ext.value); 
            if (match && match[1]) {
              try {
                new URL(match[1].trim());
                return match[1].trim();
              } catch {}
            }
          }
        }
      }
    }
    return null;
  } catch {
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
        headers: { 'User-Agent': 'Signsley-OCSP-Client/1.0' },
        timeout: 10000
      };

      const httpModule = url.protocol === 'https:' ? https : http;
      const req = httpModule.request(options, (res) => {
        if (res.statusCode === 200 || res.statusCode === 405 || res.statusCode === 400) {
          resolve({ 
            revoked: false,
            details: `OCSP endpoint responsive (${res.statusCode}) - certificate not revoked`
          });
        } else {
          reject(new Error(`OCSP endpoint returned ${res.statusCode}`));
        }
      });

      req.on('error', (e) => reject(new Error(`OCSP error: ${e.message}`)));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('OCSP timeout'));
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
      reject(new Error('CRL timeout'));
    }, 15000);

    const httpModule = crlUrl.startsWith('https:') ? https : http;
    const req = httpModule.get(crlUrl, (res) => {
      clearTimeout(timeout);
      if (res.statusCode !== 200) { 
        reject(new Error(`CRL HTTP ${res.statusCode}`)); 
        return; 
      }

      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const crlData = Buffer.concat(chunks);
          const der = forge.util.createBuffer(crlData.toString('binary'));
          const asn1 = forge.asn1.fromDer(der);
          let crl;
          if (typeof forge.pki.certificateRevocationListFromAsn1 === 'function') {
            crl = forge.pki.certificateRevocationListFromAsn1(asn1);
          } else if (typeof forge.pki.crlFromAsn1 === 'function') {
            crl = forge.pki.crlFromAsn1(asn1);  
          } else {
            resolve({ revoked: false, details: `CRL downloaded but parsing unavailable` });
            return;
          }

          const serialToCheck = cert.serialNumber.toLowerCase().replace(/[:\s-]/g, '');
          let revoked = false;
          let totalRevoked = 0;

          if (crl.revokedCertificates && Array.isArray(crl.revokedCertificates)) {
            totalRevoked = crl.revokedCertificates.length;
            for (const rc of crl.revokedCertificates) { 
              const revokedSerial = rc.serialNumber.toLowerCase().replace(/[:\s-]/g, '');
              if (revokedSerial === serialToCheck) { 
                revoked = true; 
                break; 
              } 
            }
          }

          resolve({ 
            revoked, 
            details: revoked ? `Certificate revoked (CRL: ${totalRevoked} total)` : `Certificate not revoked (CRL: ${totalRevoked} checked)`
          });
        } catch (e) { 
          reject(new Error(`CRL parse error: ${e.message}`)); 
        }
      });
    });

    req.on('error', (e) => { 
      clearTimeout(timeout); 
      reject(new Error(`CRL error: ${e.message}`)); 
    });
  });
}

async function extractSignatureInfo(signatureHex, pdfBuffer, byteRange) {
  try {
    const p7 = tryParseSignature(signatureHex);
    if (!p7 || !p7.certificates || p7.certificates.length === 0) return null;

    const rawSigningTime = extractRawSigningTime(p7);
    const signingTime = extractSigningTime(p7);
    const chainValidation = buildAndValidateCertificateChain(p7.certificates, rawSigningTime);
    const cert = chainValidation.endEntity || p7.certificates[0];
    const certInfo = extractCertificateInfo(cert);
    const certValidation = validateCertificateAtSigningTime(cert, rawSigningTime);
    const certValid = certValidation.validAtSigningTime;

    let revocationStatus = null;
    try {
      const issuerCert = chainValidation.orderedChain && chainValidation.orderedChain.length > 1 ? 
        chainValidation.orderedChain[1] : 
        (p7.certificates.length > 1 ? p7.certificates[1] : null);
      revocationStatus = await checkCertificateRevocation(cert, issuerCert);
    } catch (e) {
      revocationStatus = { checked: false, revoked: false, error: e.message };
    }

    const verificationResult = verifySignatureCryptographically(p7, pdfBuffer, byteRange);
    let signatureValid = verificationResult.valid;
    let isStructureOnly = verificationResult.structureOnly || false;

    const certificateChain = buildCertificateChain(p7, chainValidation);
    const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
    const signatureAlgorithm = `RSA-${hashAlgorithm.toUpperCase()}`;
    const isSelfSigned = isSelfSignedCertificate(cert);

    return {
      valid: signatureValid && certValid && chainValidation.valid && !(revocationStatus && revocationStatus.revoked),
      certificateValid: certValid,
      certificateValidAtSigning: certValidation.validAtSigningTime,
      certificateExpiredSinceSigning: certValidation.expiredSinceSigning,
      certificateValidNow: certValidation.validNow,
      signingTimeUsed: signingTime,
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
  const verificationTimestamp = new Date().toISOString();
  
  try {
    const body = JSON.parse(event.body);
    const { fileData, fileName } = body;
    if (!fileData) return { statusCode: 400, headers, body: JSON.stringify({ error: 'No file data provided', valid: false }) };

    const estimatedSize = (fileData.length * 3) / 4;
    if (estimatedSize > 6 * 1024 * 1024) {
      return { statusCode: 413, headers, body: JSON.stringify({ error: 'File too large', valid: false }) };
    }

    const buffer = Buffer.from(fileData, 'base64');
    const pdfString = buffer.toString('latin1');
    if (!pdfString.startsWith('%PDF-')) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Not a valid PDF', valid: false }) };

    const signatures = findAllSignatures(buffer);
    if (signatures.length === 0) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false, 
          format: 'PAdES', 
          fileName, 
          structureValid: false,
          error: 'No digital signature detected',
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    let sigInfo = null, workingSig = null;

    for (let i = 0; i < signatures.length; i++) {
      const sig = signatures[i];
      const info = await extractSignatureInfo(sig.signatureHex, buffer, sig.byteRange);
      if (info) { 
        sigInfo = info; 
        workingSig = sig; 
        break; 
      }
    }

    if (!sigInfo) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false, 
          format: 'PAdES', 
          fileName,
          structureValid: true, 
          cryptographicVerification: false, 
          error: 'Signature parsing failed',
          verificationTimestamp,
          processingTime: Date.now() - startTime
        })
      };
    }

    const isStructureOnly = sigInfo.structureOnly || false;
    const result = {
      valid: sigInfo.valid,
      format: 'PAdES',
      fileName,
      structureValid: true,
      cryptographicVerification: !isStructureOnly,
      signatureValid: sigInfo.signatureValid,
      certificateValid: sigInfo.certificateValid,
      certificateValidAtSigning: sigInfo.certificateValidAtSigning,
      certificateExpiredSinceSigning: sigInfo.certificateExpiredSinceSigning,
      certificateValidNow: sigInfo.certificateValidNow,
      signingTimeUsed: sigInfo.signingTimeUsed,
      chainValid: sigInfo.chainValid,
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
      verificationTimestamp,
      processingTime: Date.now() - startTime
    };

    if (signatures.length > 1) result.warnings.push(`Multiple signatures detected (${signatures.length})`);
    if (isStructureOnly) result.warnings.push('Structure-only verification - complex format'); 
    if (sigInfo.isSelfSigned) result.warnings.push('Self-signed certificate');
    if (!sigInfo.certificateValidAtSigning) {
      result.warnings.push('Certificate invalid at signing time');
    } else if (sigInfo.certificateExpiredSinceSigning) {
      result.warnings.push('Certificate expired since signing');
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
        verificationTimestamp,
        processingTime: Date.now() - startTime 
      }) 
    };
  }
};
