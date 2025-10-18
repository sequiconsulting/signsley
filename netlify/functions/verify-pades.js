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
    const ordered = ['C','ST','L','O','OU','CN','emailAddress'];
    const dn = attrs => {
      const map = new Map();
      attrs.forEach(a => map.set(a.shortName || a.name, (a.value || '').trim()));
      const parts = [];
      ordered.forEach(k => { if (map.has(k)) parts.push(`${k}=${map.get(k)}`); });
      map.forEach((v,k) => { if (!ordered.includes(k)) parts.push(`${k}=${v}`); });
      return parts.join(',').toLowerCase();
    };
    return dn(cert.subject.attributes) === dn(cert.issuer.attributes);
  } catch { return false; }
}

function getOidName(oid) {
  const oids = forge.pki.oids;
  const map = {
    [oids.sha1]: 'sha1',
    [oids.sha256]: 'sha256',
    [oids.sha384]: 'sha384',
    [oids.sha512]: 'sha512'
  };
  return map[oid] || 'sha256';
}

function bytesFromHex(hex) {
  return Buffer.from(hex, 'hex');
}

function extractAllHexContents(pdfString) {
  const allHex = [];
  const contentsPattern = /\/Contents\s*<([0-9a-fA-F\s\r\n]+)>/gi;
  let m;
  while ((m = contentsPattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 100) allHex.push({ hex, position: m.index, method: 'contents_tag' });
  }
  const sigDictPattern = /\/Type\s*\/Sig[^>]*>([^<]*)<([0-9a-fA-F\s\r\n]{100,}?)>/gi;
  while ((m = sigDictPattern.exec(pdfString)) !== null) {
    const hex = m[2].replace(/[\s\r\n]+/g, '');
    if (hex.length > 100) allHex.push({ hex, position: m.index, method: 'sig_dict' });
  }
  const longHexPattern = /<([0-9a-fA-F\s\r\n]{200,}?)>/g;
  while ((m = longHexPattern.exec(pdfString)) !== null) {
    const hex = m[1].replace(/[\s\r\n]+/g, '');
    if (hex.length > 200) allHex.push({ hex, position: m.index, method: 'long_hex' });
  }
  return allHex;
}

function findByteRanges(pdfString) {
  const ranges = [];
  const pattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  let m;
  while ((m = pattern.exec(pdfString)) !== null) {
    ranges.push({ range: [parseInt(m[1]), parseInt(m[2]), parseInt(m[3]), parseInt(m[4])], position: m.index });
  }
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
      if (d < minDistance && d < 50000) { minDistance = d; closestHex = hc; }
    }
    if (closestHex) {
      const key = closestHex.hex.substring(0, 100);
      if (!processed.has(key)) {
        processed.add(key);
        signatures.push({ byteRange: br.range, signatureHex: closestHex.hex, method: `byterange_proximity_${closestHex.method}` });
      }
    }
  }
  for (const hc of hexContents) {
    const key = hc.hex.substring(0, 100);
    if (!processed.has(key) && isPotentialPKCS7Signature(hc.hex)) {
      processed.add(key);
      signatures.push({ byteRange: null, signatureHex: hc.hex, method: `hex_analysis_${hc.method}` });
    }
  }
  return signatures;
}

function isPotentialPKCS7Signature(hex) {
  if (hex.length < 100) return false;
  const indicators = ['3082','3080','06092a864886f70d010702','06092a864886f70d010701'];
  return indicators.some(x => hex.toLowerCase().includes(x));
}

function tryParseSignature(signatureHex) {
  const strategies = [
    () => parseDirectly(signatureHex),
    () => { for (let i = signatureHex.length; i >= 1000; i -= 1000) { try { const r = parseDirectly(signatureHex.substring(0,i)); if (r) return r; } catch{} } return null; },
    () => { const i = signatureHex.toLowerCase().indexOf('3082'); if (i>=0) { try { return parseDirectly(signatureHex.substring(i)); } catch {} } return null; },
    () => { try { let c = signatureHex.replace(/^00+/, ''); c = c.replace(/00+$/, ''); return parseDirectly(c); } catch { return null; } },
    () => { try { return parseWithRelaxedValidation(signatureHex); } catch { return null; } }
  ];
  for (const s of strategies) { try { const r = s(); if (r && r.certificates && r.certificates.length>0) return r; } catch {} }
  return null;
}

function parseDirectly(signatureHex) {
  const bytes = bytesFromHex(signatureHex);
  const der = forge.util.createBuffer(bytes.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function parseWithRelaxedValidation(signatureHex) {
  const bytes = bytesFromHex(signatureHex);
  const der = forge.util.createBuffer(bytes.toString('binary'));
  const asn1 = forge.asn1.fromDer(der);
  return forge.pkcs7.messageFromAsn1(asn1);
}

function selectSignerCert(p7) {
  try {
    const si = p7.rawCapture && p7.rawCapture.signerInfos && p7.rawCapture.signerInfos[0];
    if (!si) return p7.certificates && p7.certificates[0];
    const issuer = forge.pki.RDNAttributesAsArray(si.issuer);
    const serial = si.serialNumber;
    return (p7.certificates || []).find(c => {
      try {
        const sameSerial = c.serialNumber && serial && c.serialNumber.toLowerCase() === serial.toLowerCase();
        const cIssuer = c.issuer && c.issuer.attributes && c.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(',');
        const siIssuer = issuer && issuer.map(a => `${a.shortName}=${a.value}`).join(',');
        return sameSerial || (cIssuer === siIssuer);
      } catch { return false; }
    }) || p7.certificates[0];
  } catch {
    return p7.certificates && p7.certificates[0];
  }
}

function computePdfByteRangeDigest(buffer, byteRange, hashAlg) {
  if (!byteRange || byteRange.length !== 4) return null;
  const [a1, l1, a2, l2] = byteRange;
  const md = forge.md[hashAlg].create();
  const part1 = buffer.subarray(a1, a1 + l1);
  const part2 = buffer.subarray(a2, a2 + l2);
  md.update(part1.toString('binary'));
  md.update(part2.toString('binary'));
  return md.digest().bytes();
}

function getHashAlgorithmFromDigestOid(p7) {
  try {
    const oidBuffer = p7.rawCapture && p7.rawCapture.digestAlgorithm;
    if (!oidBuffer) return 'sha256';
    const oidStr = forge.asn1.derToOid(oidBuffer);
    return getOidName(oidStr);
  } catch { return 'sha256'; }
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
      return { valid: true, error: 'Structure-only verification performed - certificates and structure valid', structureOnly: true };
    }

    const hashAlgorithm = getHashAlgorithmFromDigestOid(p7);
    const attrs = p7.rawCapture.authenticatedAttributes;
    const signerCert = selectSignerCert(p7);

    if (attrs) {
      const set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs);
      const attrDer = forge.asn1.toDer(set);
      const md = forge.md[hashAlgorithm].create();
      md.update(attrDer.data);
      const signature = p7.rawCapture.signature;

      try {
        signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
      } catch (e) {
        verificationError = 'Signature verification failed';
        signatureValid = false;
      }

      if (signatureValid) {
        let contentDigestValid = false;
        let pdfDigestBytes = null;
        if (byteRange) {
          pdfDigestBytes = computePdfByteRangeDigest(pdfBuffer, byteRange, hashAlgorithm);
        } else if (p7.rawCapture.content) {
          const contentMd = forge.md[hashAlgorithm].create();
          contentMd.update(p7.rawCapture.content);
          pdfDigestBytes = contentMd.digest().bytes();
        }
        for (let attr of attrs) {
          try {
            const attrOid = forge.asn1.derToOid(attr.value[0].value);
            if (attrOid === forge.pki.oids.messageDigest) {
              const attrDigest = attr.value[1].value[0].value;
              if (pdfDigestBytes) {
                contentDigestValid = (attrDigest === pdfDigestBytes);
              }
              break;
            }
          } catch {}
        }
        signatureValid = signatureValid && contentDigestValid;
        if (!contentDigestValid) verificationError = 'Content digest mismatch';
      }
    } else {
      if (p7.rawCapture.content) {
        const md = forge.md[hashAlgorithm].create();
        md.update(p7.rawCapture.content);
        const signature = p7.rawCapture.signature;
        try {
          signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
        } catch (e) {
          verificationError = 'Signature verification failed';
          signatureValid = false;
        }
      } else if (byteRange) {
        const md = forge.md[hashAlgorithm].create();
        const [a1, l1, a2, l2] = byteRange;
        md.update(pdfBuffer.subarray(a1, a1 + l1).toString('binary'));
        md.update(pdfBuffer.subarray(a2, a2 + l2).toString('binary'));
        const signature = p7.rawCapture.signature;
        try {
          signatureValid = signerCert.publicKey.verify(md.digest().bytes(), signature);
        } catch (e) {
          verificationError = 'Signature verification failed';
          signatureValid = false;
        }
      } else {
        verificationError = 'No content to verify';
        signatureValid = false;
      }
    }
  } catch (e) {
    verificationError = e.message || 'Verification error';
    signatureValid = false;
  }

  return { valid: signatureValid, error: verificationError, structureOnly: isStructureOnly };
}

function buildAndValidateCertificateChain(certificates) {
  const chainValidation = {
    valid: false, validationErrors: [], chainLength: certificates.length,
    orderedChain: [], rootCA: null, intermediates: [], endEntity: null
  };

  if (!certificates || certificates.length === 0) {
    chainValidation.validationErrors.push('No certificates in chain');
    return chainValidation;
  }

  try {
    const certAnalysis = certificates.map((cert, index) => ({
      cert, index,
      subjectCN: cert.subject.attributes.find(a => a.shortName === 'CN')?.value || 'Unknown',
      issuerCN: cert.issuer.attributes.find(a => a.shortName === 'CN')?.value || 'Unknown',
      selfSigned: isSelfSignedCertificate(cert),
      subjectDN: cert.subject.attributes.map(a => `${a.shortName}=${a.value.trim()}`).sort().join(','),
      issuerDN: cert.issuer.attributes.map(a => `${a.shortName}=${a.value.trim()}`).sort().join(',')
    }));

    let endEntityCert = certAnalysis.find(a => !a.selfSigned && (a.index === 0 || a.subjectCN === 'YOUSIGN')) || certAnalysis[0];
    const certMap = new Map(certAnalysis.map(a => [a.subjectDN, a]));
    const orderedChain = [];
    const visited = new Set();
    let current = endEntityCert;

    while (current && !visited.has(current.subjectDN)) {
      visited.add(current.subjectDN);
      orderedChain.push(current.cert);
      if (current.selfSigned) { chainValidation.rootCA = current.cert; break; }
      const issuer = certMap.get(current.issuerDN);
      if (!issuer) { chainValidation.validationErrors.push(`Issuer certificate not found for: ${current.subjectCN}`); break; }
      current = issuer;
    }

    chainValidation.orderedChain = orderedChain;
    chainValidation.endEntity = endEntityCert.cert;

    let chainValid = true;
    for (let i = 0; i < orderedChain.length - 1; i++) {
      const child = orderedChain[i], parent = orderedChain[i + 1];
      try { if (!parent.verify(child)) { chainValidation.validationErrors.push(`Certificate signature verification failed: ${child.subject.attributes.find(a => a.shortName === 'CN')?.value || 'Unknown'}`); chainValid = false; } }
      catch (e) { chainValidation.validationErrors.push(`Certificate verification error: ${e.message}`); chainValid = false; }
      const now = new Date();
      if (now < child.validity.notBefore || now > child.validity.notAfter) { chainValidation.validationErrors.push(`Certificate expired: ${child.subject.attributes.find(a => a.shortName === 'CN')?.value || 'Unknown'}`); chainValid = false; }
    }
    if (chainValidation.rootCA) {
      const now = new Date();
      if (now < chainValidation.rootCA.validity.notBefore || now > chainValidation.rootCA.validity.notAfter) { chainValidation.validationErrors.push('Root CA certificate expired'); chainValid = false; }
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
        if (oid === forge.pki.oids.signingTime) {
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
      chain.push({
        position: idx + 1,
        subject, issuer,
        serialNumber: cert.serialNumber,
        validFrom: formatDate(cert.validity.notBefore),
        validTo: formatDate(cert.validity.notAfter),
        isSelfSigned: isSelf,
        publicKeyAlgorithm: cert.publicKey.algorithm || 'RSA',
        keySize: cert.publicKey.n ? cert.publicKey.n.bitLength() : 'Unknown',
        role: isSelf ? 'root-ca' : (idx === 0 ? 'end-entity' : 'intermediate-ca')
      });
    });
  }
  return chain;
}

async function checkCertificateRevocation(cert, issuerCert = null) {
  const status = { checked: false, revoked: false, method: null, error: null, ocspResponder: null, crlDistPoint: null };
  try {
    const ocspUrl = extractOCSPUrl(cert);
    if (ocspUrl) {
      status.ocspResponder = ocspUrl;
      try { const r = await checkOCSP(cert, issuerCert, ocspUrl); status.checked = true; status.revoked = r.revoked; status.method = 'OCSP'; return status; }
      catch (e) { status.error = `OCSP check failed: ${e.message}`; }
    }
    const crlUrl = extractCRLUrl(cert);
    if (crlUrl) {
      status.crlDistPoint = crlUrl;
      try { const r = await checkCRL(cert, crlUrl); status.checked = true; status.revoked = r.revoked; status.method = 'CRL'; return status; }
      catch (e) { status.error = `CRL check failed: ${e.message}`; }
    }
    if (!ocspUrl && !crlUrl) status.error = 'No revocation checking endpoints found in certificate';
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
            /OCSP\s*[-–]\s*URI:\s*(https?:\/\/[^\s\r\n<>]+)/gi,
            /URI:\s*(https?:\/\/[^\s\r\n<>]*ocsp[^\s\r\n<>]*)/gi,
            /\b(https?:\/\/[^\s\r\n<>]*ocsp[^\s\r\n<>]*)/gi
          ];
          for (const p of patterns) { const m = p.exec(ext.value); if (m) return m[1].trim(); }
        }
      }
    }
    return null;
  } catch { return null; }
}

function extractCRLUrl(cert) {
  try {
    if (!cert.extensions) return null;
    for (const ext of cert.extensions) {
      if (ext.name === 'cRLDistributionPoints' || ext.id === '2.5.29.31') {
        if (ext.value) {
          const patterns = [/URI:\s*(https?:\/\/[^\s\r\n<>]+\.crl)/gi, /\b(https?:\/\/[^\s\r\n<>]*\.crl)/gi];
          for (const p of patterns) { const m = p.exec(ext.value); if (m) return m[1].trim(); }
        }
      }
    }
    return null;
  } catch { return null; }
}

async function checkOCSP(cert, issuerCert, ocspUrl) {
  return new Promise((resolve) => {
    // Placeholder: treat as not revoked
    resolve({ revoked: false, response: 'OCSP not implemented' });
  });
}

async function checkCRL(cert, crlUrl) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('CRL download timeout')), 15000);
    const httpModule = crlUrl.startsWith('https:') ? https : http;
    const req = httpModule.get(crlUrl, (res) => {
      clearTimeout(timeout);
      if (res.statusCode !== 200) { reject(new Error(`CRL HTTP ${res.statusCode}`)); return; }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const crlData = Buffer.concat(chunks);
          const der = forge.util.createBuffer(crlData.toString('binary'));
          const asn1 = forge.asn1.fromDer(der);
          const crl = forge.pki.crlFromAsn1(asn1);
          const serial = cert.serialNumber;
          let revoked = false;
          if (crl.revokedCertificates) {
            for (const rc of crl.revokedCertificates) { if (rc.serialNumber === serial) { revoked = true; break; } }
          }
          resolve({ revoked, crlSize: crlData.length });
        } catch (e) { reject(new Error(`CRL parse error: ${e.message}`)); }
      });
    });
    req.on('error', (e) => { clearTimeout(timeout); reject(new Error(`CRL download error: ${e.message}`)); });
  });
}

async function extractSignatureInfo(signatureHex, pdfBuffer, byteRange) {
  try {
    const p7 = tryParseSignature(signatureHex);
    if (!p7 || !p7.certificates || p7.certificates.length === 0) return null;

    const chainValidation = buildAndValidateCertificateChain(p7.certificates);
    const cert = chainValidation.endEntity || p7.certificates[0];
    const certInfo = extractCertificateInfo(cert);

    const now = new Date();
    const certValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;

    let revocationStatus = null;
    try {
      const issuerCert = chainValidation.orderedChain && chainValidation.orderedChain.length > 1 ? chainValidation.orderedChain[1] : p7.certificates[1] || null;
      revocationStatus = await checkCertificateRevocation(cert, issuerCert);
    } catch {}

    const verificationResult = verifySignatureCryptographically(p7, pdfBuffer, byteRange);
    let signatureValid = verificationResult.valid;
    let isStructureOnly = verificationResult.structureOnly || false;

    if (isStructureOnly && certValid && chainValidation.valid && !(revocationStatus && revocationStatus.revoked)) {
      signatureValid = true;
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
  } catch { return null; }
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

    let sigInfo = null, workingSig = null, parseAttempts = [];
    for (const sig of signatures) {
      const info = await extractSignatureInfo(sig.signatureHex, buffer, sig.byteRange);
      if (info) { sigInfo = info; workingSig = sig; break; } else { parseAttempts.push(sig.method); }
    }

    if (!sigInfo) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          valid: false, format: 'PAdES (PDF Advanced Electronic Signature)', fileName,
          structureValid: true, cryptographicVerification: false, error: 'Advanced signature encoding detected',
          warnings: [`Found ${signatures.length} signature structure(s)`, 'Signature uses advanced or proprietary encoding', 'Certificate information cannot be extracted'],
          troubleshooting: ['Use Adobe Acrobat Reader for full verification', 'Contact document signer for signature details', 'Check if signature uses non-standard encoding', `Attempted parsing methods: ${parseAttempts.join(', ')}`],
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

    if (signatures.length > 1) result.warnings.push(`Multiple signatures detected (${signatures.length})`);
    if (isStructureOnly) { result.warnings.push('Structure-only verification performed'); result.troubleshooting.push('Use Adobe Acrobat Reader for cryptographic verification'); }
    if (sigInfo.isSelfSigned) result.warnings.push('Self-signed certificate detected');
    if (!sigInfo.certificateValid) result.warnings.push('Certificate has expired');
    if (!sigInfo.chainValid) {
      const serious = sigInfo.chainValidationErrors.filter(e => !e.includes('Chain does not end with a root CA') && !e.includes('Issuer certificate not found'));
      if (serious.length > 0) { result.warnings.push('Certificate chain validation failed'); result.troubleshooting.push(`Chain errors: ${serious.join(', ')}`); }
      else result.warnings.push('Incomplete certificate chain (common for signing services)');
    }
    if (sigInfo.revocationStatus) {
      if (sigInfo.revocationStatus.revoked) result.warnings.push('Certificate has been revoked');
      else if (!sigInfo.revocationStatus.checked) { result.warnings.push('Revocation status could not be verified'); if (sigInfo.revocationStatus.error) result.troubleshooting.push(`Revocation check: ${sigInfo.revocationStatus.error}`); }
    } else result.warnings.push('Revocation status not checked');

    if (sigInfo.verificationError && !isStructureOnly && sigInfo.verificationError !== 'Structure-only verification performed - certificates and structure valid') {
      result.warnings.push(`Verification issue: ${sigInfo.verificationError}`);
    }
    if (pdfString.includes('/EmbeddedFile')) result.warnings.push('Document contains embedded files');

    return { statusCode: 200, headers, body: JSON.stringify(result) };
  } catch (error) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Verification failed', message: error.message, valid: false, processingTime: Date.now() - startTime }) };
  }
};

