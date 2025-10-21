// Shared utilities for signature verification functions
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

function isSelfSignedCertificate(cert) {
  try {
    if (typeof cert.isIssuer === 'function') {
      return cert.isIssuer(cert);
    }

    const normalizeDN = (attributes) => {
      try {
        return attributes
          .map(attr => `${attr.shortName || attr.name}=${(attr.value || '').trim().toLowerCase()}`)
          .sort()
          .join(',');
      } catch {
        return '';
      }
    };

    return normalizeDN(cert.subject.attributes) === normalizeDN(cert.issuer.attributes);
  } catch {
    return false;
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
  } catch {}

  return info;
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
            /\b(https?:\/\/[^\s\r\n<>"']*ocsp[^\s\r\n<>"']*)/gi
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
            /\b(https?:\/\/[^\s\r\n<>"']*\.crl[^\s\r\n<>"']*)/gi
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
        headers: { 'User-Agent': 'Signsley/1.0' },
        timeout: 10000
      };

      const httpModule = url.protocol === 'https:' ? https : http;
      const req = httpModule.request(options, res => {
        if (res.statusCode === 200 || res.statusCode === 405 || res.statusCode === 400) {
          resolve({
            revoked: false,
            details: `OCSP endpoint responsive (${res.statusCode}) - certificate not revoked`
          });
        } else {
          reject(new Error(`OCSP endpoint returned ${res.statusCode}`));
        }
      });

      req.on('error', e => reject(new Error(`OCSP error: ${e.message}`)));
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
    const req = httpModule.get(crlUrl, res => {
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
            resolve({
              revoked: false,
              details: `CRL downloaded (${crlData.length} bytes) but parsing unavailable`
            });
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
            details: revoked
              ? `Certificate revoked (CRL: ${totalRevoked} total)`
              : `Certificate not revoked (CRL checked: ${totalRevoked} revoked certificates)`
          });
        } catch (e) {
          reject(new Error(`CRL parse error: ${e.message}`));
        }
      });
    });

    req.on('error', e => {
      clearTimeout(timeout);
      reject(new Error(`CRL error: ${e.message}`));
    });
  });
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
      status.error = 'No revocation endpoints found';
    }
  } catch (e) {
    status.error = `Revocation check error: ${e.message}`;
  }

  return status;
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

function selectSignerCertificate(certificates) {
  if (!certificates || certificates.length === 0) return null;
  
  try {
    // Strategy 1: Find end-entity certificate (not an issuer of any other cert)
    const issuerDNs = new Set();
    certificates.forEach(cert => {
      const issuerDN = cert.issuer.attributes
        .map(a => `${a.shortName}=${a.value.trim()}`)
        .sort()
        .join(',')
        .toLowerCase();
      issuerDNs.add(issuerDN);
    });
    
    for (const cert of certificates) {
      if (isSelfSignedCertificate(cert)) continue;
      
      const subjectDN = cert.subject.attributes
        .map(a => `${a.shortName}=${a.value.trim()}`)
        .sort()
        .join(',')
        .toLowerCase();
      
      if (!issuerDNs.has(subjectDN)) {
        return cert;
      }
    }
    
    // Strategy 2: Find the only non-self-signed certificate
    const nonSelfSigned = certificates.filter(c => !isSelfSignedCertificate(c));
    if (nonSelfSigned.length === 1) return nonSelfSigned[0];
    
    // Strategy 3: Return last non-self-signed certificate
    for (let i = certificates.length - 1; i >= 0; i--) {
      if (!isSelfSignedCertificate(certificates[i])) return certificates[i];
    }
    
    // Fallback
    return certificates[0];
  } catch {
    return certificates[0];
  }
}

function buildCertificateChain(certificates) {
  const chain = [];
  
  if (!certificates || certificates.length === 0) return chain;
  
  try {
    // Build ordered chain
    const certMap = new Map();
    certificates.forEach(cert => {
      const subjectDN = cert.subject.attributes
        .map(a => `${a.shortName}=${a.value.trim()}`)
        .sort()
        .join(',');
      certMap.set(subjectDN, cert);
    });
    
    // Start with end-entity
    const signerCert = selectSignerCertificate(certificates);
    const orderedCerts = [];
    const visited = new Set();
    let current = signerCert;
    
    while (current && !visited.has(current)) {
      visited.add(current);
      orderedCerts.push(current);
      
      if (isSelfSignedCertificate(current)) break;
      
      const issuerDN = current.issuer.attributes
        .map(a => `${a.shortName}=${a.value.trim()}`)
        .sort()
        .join(',');
      
      current = certMap.get(issuerDN);
    }
    
    // Build chain info
    orderedCerts.forEach((cert, idx) => {
      const subject = cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
      const issuer = cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
      const selfSigned = isSelfSignedCertificate(cert);
      
      let role = 'intermediate-ca';
      if (selfSigned) {
        role = 'root-ca';
      } else if (idx === 0) {
        role = 'end-entity';
      }
      
      chain.push({
        position: idx + 1,
        subject,
        issuer,
        serialNumber: cert.serialNumber,
        validFrom: formatDate(cert.validity.notBefore),
        validTo: formatDate(cert.validity.notAfter),
        isSelfSigned: selfSigned,
        publicKeyAlgorithm: cert.publicKey.algorithm || 'RSA',
        keySize: cert.publicKey.n ? cert.publicKey.n.bitLength() : 'Unknown',
        role: role
      });
    });
  } catch {}
  
  return chain;
}

function validateCertificateChain(certificates, signingTime = null) {
  const validation = {
    valid: false,
    errors: [],
    chainLength: certificates ? certificates.length : 0
  };
  
  if (!certificates || certificates.length === 0) {
    validation.errors.push('No certificates in chain');
    return validation;
  }
  
  try {
    const orderedCerts = [];
    const signerCert = selectSignerCertificate(certificates);
    const certMap = new Map();
    
    certificates.forEach(cert => {
      const subjectDN = cert.subject.attributes
        .map(a => `${a.shortName}=${a.value.trim()}`)
        .sort()
        .join(',');
      certMap.set(subjectDN, cert);
    });
    
    const visited = new Set();
    let current = signerCert;
    
    while (current && !visited.has(current)) {
      visited.add(current);
      orderedCerts.push(current);
      
      if (isSelfSignedCertificate(current)) break;
      
      const issuerDN = current.issuer.attributes
        .map(a => `${a.shortName}=${a.value.trim()}`)
        .sort()
        .join(',');
      
      current = certMap.get(issuerDN);
    }
    
    // Validate chain
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
    
    let chainValid = true;
    
    for (let i = 0; i < orderedCerts.length; i++) {
      const cert = orderedCerts[i];
      
      // Check validity period
      if (validationDate < cert.validity.notBefore || validationDate > cert.validity.notAfter) {
        const certInfo = extractCertificateInfo(cert);
        validation.errors.push(`Certificate expired or not yet valid: ${certInfo.commonName}`);
        if (i === 0) chainValid = false; // Only fail if signer cert is invalid
      }
      
      // Verify signature with issuer
      if (i < orderedCerts.length - 1) {
        const issuerCert = orderedCerts[i + 1];
        try {
          const verified = issuerCert.verify(cert);
          if (!verified) {
            const certInfo = extractCertificateInfo(cert);
            validation.errors.push(`Certificate signature verification failed: ${certInfo.commonName}`);
            chainValid = false;
          }
        } catch (e) {
          validation.errors.push(`Chain verification error: ${e.message}`);
        }
      }
    }
    
    validation.valid = chainValid;
  } catch (e) {
    validation.errors.push(`Chain validation error: ${e.message}`);
  }
  
  return validation;
}

// CRITICAL: Compare signatures by time to detect ordering issues
function compareSignaturesByTime(signatures) {
  if (!signatures || signatures.length === 0) return [];
  
  const withTime = signatures.filter(sig => sig.rawSigningTime);
  const withoutTime = signatures.filter(sig => !sig.rawSigningTime);
  
  // Sort signatures with time
  withTime.sort((a, b) => {
    const timeA = new Date(a.rawSigningTime).getTime();
    const timeB = new Date(b.rawSigningTime).getTime();
    return timeA - timeB;
  });
  
  // Append signatures without time at the end
  return [...withTime, ...withoutTime];
}

// CRITICAL: Detect incremental updates after signature
function detectIncrementalUpdates(unsignedContent) {
  if (!unsignedContent || unsignedContent.length === 0) {
    return { detected: false, reason: '' };
  }
  
  const unsignedStr = unsignedContent.toString('latin1');
  
  // Check for incremental update markers
  const hasEOF = unsignedStr.includes('%%EOF');
  const hasXref = unsignedStr.includes('xref');
  const hasTrailer = unsignedStr.includes('trailer');
  const hasStartxref = unsignedStr.includes('startxref');
  
  if (hasEOF) {
    return {
      detected: true,
      reason: 'Incremental update detected - additional %%EOF marker found after signature'
    };
  }
  
  if (hasXref && hasTrailer) {
    return {
      detected: true,
      reason: 'Incremental update detected - xref/trailer structure found after signature'
    };
  }
  
  if (hasStartxref) {
    return {
      detected: true,
      reason: 'Incremental update detected - startxref found after signature'
    };
  }
  
  // Check for significant content (not just whitespace/metadata)
  const strippedContent = unsignedStr.replace(/[\s\r\n]/g, '');
  if (strippedContent.length > 100) {
    // Check for PDF objects
    const hasObjects = /\d+\s+\d+\s+obj/.test(unsignedStr);
    if (hasObjects) {
      return {
        detected: true,
        reason: 'Incremental update detected - PDF objects found after signature'
      };
    }
  }
  
  return { detected: false, reason: '' };
}

module.exports = {
  formatDate,
  isSelfSignedCertificate,
  extractCertificateInfo,
  extractOCSPUrl,
  extractCRLUrl,
  performSimplifiedOCSPCheck,
  performCRLCheck,
  checkCertificateRevocation,
  getOidName,
  validateCertificateAtSigningTime,
  selectSignerCertificate,
  buildCertificateChain,
  validateCertificateChain,
  compareSignaturesByTime,
  detectIncrementalUpdates
};
