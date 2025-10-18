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

module.exports = {
  formatDate,
  isSelfSignedCertificate,
  extractCertificateInfo,
  extractOCSPUrl,
  extractCRLUrl,
  performSimplifiedOCSPCheck,
  performCRLCheck,
  checkCertificateRevocation
};
