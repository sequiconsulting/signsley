// Signsley v4.1 - Fixed integrity detection logic
const uploadSection = document.getElementById('uploadSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetails = document.getElementById('resultDetails');
const errorMessage = document.getElementById('errorMessage');

const MAX_FILE_SIZE = 6 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = ['pdf', 'xml', 'p7m', 'p7s', 'sig'];
const REQUEST_TIMEOUT = 120000;

document.addEventListener('DOMContentLoaded', () => {
  hideLoading();
  hideError();
  attachEventDelegation();
});

function attachEventDelegation() {
  document.addEventListener('click', (e) => {
    const toggle = e.target.closest('[data-chain-toggle]');
    if (toggle) {
      e.preventDefault();
      const targetId = toggle.getAttribute('data-chain-toggle');
      const panel = document.getElementById(targetId);
      if (panel) panel.style.display = panel.style.display === 'block' ? 'none' : 'block';
    }
  });
}

window.handleFile = handleFile;

if (fileInput) {
  const onPick = (e) => {
    const f = e.target?.files?.[0];
    if (f) handleFile(f);
  };
  fileInput.addEventListener('change', onPick);
  fileInput.addEventListener('input', onPick);
}

if (uploadSection) {
  ['dragenter', 'dragover'].forEach(evt =>
    uploadSection.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      uploadSection.classList.add('dragover');
    })
  );
  ['dragleave', 'drop'].forEach(evt =>
    uploadSection.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (evt === 'drop') {
        const dt = e.dataTransfer;
        if (dt?.files?.[0]) handleFile(dt.files[0]);
      }
      uploadSection.classList.remove('dragover');
    })
  );
}

if (browseBtn) {
  browseBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (fileInput) {
      fileInput.value = '';
      requestAnimationFrame(() => fileInput.click());
    }
  });
}

async function handleFile(file) {
  hideError();
  hideResults();

  try {
    validateFile(file);
    showLoading('Verifying signature...');

    const arrayBuffer = await file.arrayBuffer();
    const base64Data = arrayBufferToBase64Optimized(arrayBuffer);
    const endpoint = determineEndpoint(file, arrayBuffer);
    const result = await sendVerificationRequest(endpoint, base64Data, sanitizeFileName(file.name));

    hideLoading();
    displayResults(result);
  } catch (err) {
    console.error('Processing error:', err);
    hideLoading();
    showError(err.message || 'Verification failed');
  }
}

function validateFile(file) {
  if (!file) throw new Error('No file selected');
  if (file.size === 0) throw new Error('File is empty');
  if (file.size > MAX_FILE_SIZE) throw new Error('File too large (max 6MB)');

  const ext = getFileExtension(file.name);
  if (!SUPPORTED_EXTENSIONS.includes(ext)) {
    throw new Error('Unsupported file type. Supported: PDF, XML, P7M, P7S, SIG');
  }
}

function sanitizeFileName(fileName) {
  return fileName.replace(/[^\w\s.-]/gi, '').substring(0, 255);
}

function getFileExtension(fileName) {
  return (fileName.split('.').pop() || '').toLowerCase();
}

function determineEndpoint(file, arrayBuffer) {
  const ext = getFileExtension(file.name);
  const endpointMap = {
    pdf: '/.netlify/functions/verify-pades',
    xml: '/.netlify/functions/verify-xades',
    p7m: '/.netlify/functions/verify-cades',
    p7s: '/.netlify/functions/verify-cades',
    sig: '/.netlify/functions/verify-cades'
  };

  if (endpointMap[ext]) return endpointMap[ext];

  const head = new Uint8Array(arrayBuffer.slice(0, 1024));
  const str = new TextDecoder('utf-8', { fatal: false }).decode(head);

  if (str.includes('%PDF')) return '/.netlify/functions/verify-pades';
  if (str.includes('<?xml') || str.includes('<')) return '/.netlify/functions/verify-xades';
  return '/.netlify/functions/verify-cades';
}

function arrayBufferToBase64Optimized(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode.apply(null, Array.from(chunk));
  }

  return btoa(binary);
}

async function sendVerificationRequest(endpoint, base64Data, fileName) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileData: base64Data, fileName }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server error: ${response.status}`);
    }

    return await response.json();
  } catch (e) {
    clearTimeout(timeoutId);
    if (e.name === 'AbortError') {
      throw new Error('Request timeout - processing may require more time');
    }
    throw e;
  }
}

function formatUTCTimestamp(isoString) {
  if (!isoString) return 'Unknown';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return 'Unknown';
    
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    const hours = String(date.getUTCHours()).padStart(2, '0');
    const minutes = String(date.getUTCMinutes()).padStart(2, '0');
    const seconds = String(date.getUTCSeconds()).padStart(2, '0');
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
  } catch {
    return 'Unknown';
  }
}

// FIXED: Corrected file integrity detection logic

function determineFileIntegrityEnhanced(result) {
  // No signature detected
  if (result?.error === 'No digital signature detected') return null;
  
  // Backend explicitly states integrity (trust it)
  if (typeof result.documentIntact === 'boolean') return result.documentIntact;
  
  // Hash digest match from backend (authoritative)
  if (typeof result.referenceDigestMatch === 'boolean') return result.referenceDigestMatch;
  if (typeof result.contentDigestMatch === 'boolean') return result.contentDigestMatch;

  // Core integrity check: cryptographic hash verification
  const cryptoPerformed = result.cryptographicVerification === true;
  const hashMatches = result.signatureValid === true;
  
  // If hash verification was performed
  if (cryptoPerformed) {
    // Hash matches → document intact
    // Hash doesn't match → document modified
    return hashMatches;
  }
  
  // Crypto verification not performed → cannot determine
  return null;
}

function getIntegrityStatusMessage(integrityStatus, result) {
  if (integrityStatus === true) {
    return {
      status: '✅ Document Intact',
      detail: 'Cryptographic verification confirms document unchanged since signing',
      color: '#2c5f2d'
    };
  }

  if (integrityStatus === false) {
    return {
      status: '❌ Document Modified',
      detail: 'Document content altered after signature was applied',
      color: '#c62828'
    };
  }

  if (result?.error === 'No digital signature detected') {
    return {
      status: '⚠️ Integrity Unknown',
      detail: 'No embedded signature found',
      color: '#f57c00'
    };
  }

  if (result.certificateExpiredSinceSigning === true) {
    return {
      status: '✅ Document Intact (Cert Expired)',
      detail: 'Document unchanged, certificate expired since signing',
      color: '#f57c00'
    };
  }

  return {
    status: '⚠️ Integrity Unknown',
    detail: 'Cannot definitively verify integrity - structure-only verification',
    color: '#f57c00'
  };
}

function determineSignatureStatusWithIntegrityOverride(result) {
  const integrity = determineFileIntegrityEnhanced(result);

  if (integrity === false) {
    return {
      icon: '❌',
      class: 'invalid',
      title: 'Document Modified - Signatures Invalid',
      description: 'Document altered after signing'
    };
  }

  if (result?.error === 'No digital signature detected') {
    return {
      icon: '⚠️',
      class: 'warning',
      title: 'No Embedded Signature',
      description: 'No digital signature found'
    };
  }

  const multi = extractMultipleSignatureInfo(result);
  const multiFlag = multi.count > 1;

  const sigOK = result.signatureValid === true;
  const certValidAtSigning = result.certificateValidAtSigning !== false;
  const certExpiredSince = result.certificateExpiredSinceSigning === true;
  const chainOK = result.chainValid !== false;
  const revOK = !result.revoked;

  if (sigOK && certValidAtSigning && chainOK && revOK && certExpiredSince) {
    return {
      icon: '⏰',
      class: 'expired',
      title: multiFlag ? 'Valid Signatures - Cert Expired' : 'Valid Signature - Cert Expired',
      description: multiFlag
        ? 'Signatures valid when created, certificates expired since'
        : 'Signature valid when created, certificate expired since'
    };
  }

  if (sigOK && !certValidAtSigning) {
    return {
      icon: '❌',
      class: 'invalid',
      title: 'Invalid Certificate',
      description: 'Certificate not valid at signing time'
    };
  }

  const certOK = result.certificateValid;
  const certExp = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());

  if (result.valid && sigOK && certOK && chainOK && revOK && !certExp) {
    return {
      icon: '✅',
      class: 'valid',
      title: multiFlag ? 'Multiple Signatures Verified' : 'Signature Verified',
      description: multiFlag ? `All ${multi.count} signatures valid` : 'All components valid'
    };
  }

  if (sigOK && certOK && chainOK && !revOK) {
    return {
      icon: '🚫',
      class: 'invalid',
      title: 'Certificate Revoked',
      description: 'Certificate has been revoked'
    };
  }

  if (sigOK && chainOK && certExp && !certExpiredSince) {
    return {
      icon: '⏰',
      class: 'expired',
      title: multiFlag ? 'Valid Signatures - Cert Expired' : 'Valid Signature - Cert Expired',
      description: 'Certificate expired'
    };
  }

  if (result.structureValid && !result.cryptographicVerification) {
    return {
      icon: '📋',
      class: 'info',
      title: 'Signature Structure Valid',
      description: 'Structure verified - crypto validation not performed'
    };
  }

  if (result.structureValid && !sigOK) {
    return {
      icon: '❌',
      class: 'invalid',
      title: 'Invalid Signature',
      description: 'Cryptographic validation failed'
    };
  }

  if (!result.structureValid) {
    return {
      icon: '❌',
      class: 'invalid',
      title: 'Corrupted Structure',
      description: 'Signature structure damaged'
    };
  }

  return {
    icon: '❌',
    class: 'invalid',
    title: 'No Valid Signature',
    description: 'No valid signature found'
  };
}

function extractMultipleSignatureInfo(result) {
  let count = 1;
  if (Array.isArray(result.signatures)) count = Math.max(count, result.signatures.length);
  if (Array.isArray(result.signatureDetails)) count = Math.max(count, result.signatureDetails.length);
  if (typeof result.signatureCount === 'number') count = Math.max(count, result.signatureCount);
  if (result.warnings) {
    for (const w of result.warnings) {
      const m = w.match(/Multiple signatures detected\s*\((\d+)\)/i);
      if (m) {
        count = Math.max(count, parseInt(m[1]));
        break;
      }
    }
  }
  return { count };
}

function displayResults(result) {
  if (!result) {
    showError('Invalid result');
    return;
  }

  const integrity = determineFileIntegrityEnhanced(result);
  const integrityMsg = getIntegrityStatusMessage(integrity, result);
  const main = integrity === false
    ? {
        icon: '❌',
        class: 'invalid',
        title: 'Document Modified',
        description: 'Document altered after signing'
      }
    : determineSignatureStatusWithIntegrityOverride(result);

  resultIcon.textContent = main.icon;
  resultIcon.className = 'result-icon ' + main.class;
  resultTitle.textContent = main.title;

  let html = '';

  html += `<div class="integrity-section" style="margin-bottom:1.25rem;padding:0.9rem 1rem;background:var(--bg-secondary);border-radius:var(--radius);border-left:4px solid ${integrityMsg.color};">`;
  html += `<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.4rem;">🛡️ File Integrity</div>`;
  html += `<div style="color:${integrityMsg.color};font-weight:500;font-size:0.875rem;">${integrityMsg.status}</div>`;
  html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.2rem;">${esc(integrityMsg.detail)}</div>`;
  html += `</div>`;

  const multi = extractMultipleSignatureInfo(result);
  if (multi.count > 1) {
    html += '<div class="signature-info-section" style="margin-bottom:1.25rem;padding:0.9rem 1rem;background:var(--bg-secondary);border-radius:var(--radius);border-left:4px solid #2c5f2d;">';
    html += '<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.4rem;">📝 Signatures</div>';
    html += '<div style="color:#2c5f2d;font-weight:500;font-size:0.875rem;">✅ Multiple Detected</div>';
    html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.2rem;">${multi.count} digital signatures</div>`;
    html += '</div>';
  }

  const sigs = getSignaturesArray(result);
  if (sigs.length > 0 && !(result?.error === 'No digital signature detected')) {
    html += renderSignatureCards(sigs, integrity);
  }

  if (result.error) {
    html += row('Status', esc(result.error), !result.cryptographicVerification ? '#2196f3' : '#f57c00');
  }

  html += row('File', esc(result.fileName));
  html += row('Format', esc(result.format));

  if (result.verificationTimestamp) {
    html += row('Verified (UTC)', formatUTCTimestamp(result.verificationTimestamp), '#2196f3');
  }

  if (result.processingTime) html += row('Processing', `${result.processingTime}ms`);

  if (result.cryptographicVerification !== undefined) {
    const st = result.cryptographicVerification ? '✅ Full Verification' : '📋 Structure Analysis';
    const col = result.cryptographicVerification ? '#2c5f2d' : '#2196f3';
    html += row('Verification', st, col);
  }

  if (result.structureValid !== undefined) {
    html += row('Structure', result.structureValid ? '✅ Valid' : '❌ Invalid', result.structureValid ? '#2c5f2d' : '#c62828');
  }

  if (result.certificateValid !== undefined && !(result?.error === 'No digital signature detected')) {
    const certExp = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
    let txt, col;
    if (result.certificateValid && !certExp) {
      txt = '✅ Valid';
      col = '#2c5f2d';
    } else if (result.certificateValid && certExp) {
      txt = '⏰ Valid but Expired';
      col = '#f57c00';
    } else {
      txt = '❌ Invalid';
      col = '#c62828';
    }
    html += row('Certificate', txt, col);
  }

  if (result.chainValidationPerformed !== undefined && !(result?.error === 'No digital signature detected')) {
    html += row('Chain', result.chainValid ? '✅ Valid' : '⚠️ Issues', result.chainValid ? '#2c5f2d' : '#f57c00');
  }

  if (result.revocationChecked !== undefined && !(result?.error === 'No digital signature detected')) {
    let txt, col;
    if (result.revocationChecked) {
      if (result.revoked) {
        txt = '🚫 Revoked';
        col = '#c62828';
      } else {
        txt = '✅ Not Revoked';
        col = '#2c5f2d';
      }
    } else {
      txt = '⚠️ Not Checked';
      col = '#f57c00';
    }
    html += row('Revocation', txt, col);
  }

  addIfPresent('Detection', result.detectionMethod);

  if (result.troubleshooting?.length > 0) {
    const tips = result.troubleshooting.slice(0, 3).map(t => `💡 ${esc(t)}`).join('<br>');
    html += row('Notes', tips, '#2196f3');
  }

  function addIfPresent(label, value) {
    if (value && value !== 'Unknown') html += row(label, esc(value));
  }

  resultDetails.innerHTML = html;
  results.classList.add('show');
}

function getSignaturesArray(result) {
  if (Array.isArray(result.signatures) && result.signatures.length > 0) return result.signatures;
  if (Array.isArray(result.signatureDetails) && result.signatureDetails.length > 0) return result.signatureDetails;

  const f = {
    signatureValid: result.signatureValid,
    certificateValid: result.certificateValid,
    certificateValidAtSigning: result.certificateValidAtSigning,
    certificateExpiredSinceSigning: result.certificateExpiredSinceSigning,
    chainValid: result.chainValid,
    revocationChecked: result.revocationChecked,
    revoked: result.revoked,
    signedBy: result.signedBy,
    organization: result.organization,
    email: result.email,
    signingTime: result.signatureDate || result.signingTime,
    signatureAlgorithm: result.signatureAlgorithm,
    certificateIssuer: result.certificateIssuer,
    certificateValidFrom: result.certificateValidFrom,
    certificateValidTo: result.certificateValidTo,
    serialNumber: result.serialNumber,
    isSelfSigned: result.isSelfSigned,
    certificateChain: result.certificateChain
  };

  const any = Object.values(f).some(v => v !== undefined && v !== null && v !== 'Unknown');
  return any ? [f] : [];
}

function renderSignatureCards(signatures, integrity) {
  if (!Array.isArray(signatures) || signatures.length === 0) return '';

  return signatures.map((sig, i) => {
    const forcedInvalid = integrity === false;
    const ok = !forcedInvalid && sig.signatureValid === true && sig.certificateValid !== false && sig.chainValid !== false && sig.revoked !== true;
    const bar = forcedInvalid ? '#c62828' : ok ? '#2c5f2d' : sig.signatureValid === false ? '#c62828' : '#f57c00';

    let chips = '';

    if (forcedInvalid) {
      chips += chip('Invalid', '#c62828');
    } else {
      chips += chip(sig.signatureValid === true ? 'Valid' : sig.signatureValid === false ? 'Invalid' : 'Unknown', 
        sig.signatureValid === true ? '#2c5f2d' : sig.signatureValid === false ? '#c62828' : '#f57c00');

      let certText = 'Cert: Valid', certColor = '#2c5f2d';
      if (sig.certificateValidAtSigning !== undefined) {
        if (sig.certificateValidAtSigning && sig.certificateExpiredSinceSigning) {
          certText = 'Cert: Expired Since';
          certColor = '#f57c00';
        } else if (!sig.certificateValidAtSigning) {
          certText = 'Cert: Invalid';
          certColor = '#c62828';
        }
      }
      chips += chip(certText, certColor);

      if (sig.chainValidationPerformed) {
        chips += chip(sig.chainValid ? 'Chain: OK' : 'Chain: Issues', sig.chainValid ? '#2c5f2d' : '#f57c00');
      }

      if (sig.revocationChecked) {
        chips += chip(sig.revoked ? 'Revoked' : 'Not Revoked', sig.revoked ? '#c62828' : '#2c5f2d');
      }
    }

const detailRow = (l, v) => {
  if (!v && v !== 0) return '';
  return `<div class="detail-row"><div class="detail-label">${esc(l)}</div><div class="detail-value">${esc(String(v))}</div></div>`;
};


    const chainId = `chain-panel-sig-${i + 1}`;
    let chainHtml = '';

    if (Array.isArray(sig.certificateChain) && sig.certificateChain.length > 0) {
      chainHtml += `<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border);">`;
      chainHtml += `<div class="chain-toggle" data-chain-toggle="${chainId}" style="cursor:pointer;display:inline-flex;align-items:center;gap:6px;color:#2196f3;font-weight:600;font-size:0.8rem;">` +
        `<span>🔗 Certificate Chain (${sig.certificateChain.length})</span></div>`;
      chainHtml += `<div class="chain-panel" id="${chainId}" style="display:none;margin-top:0.75rem;padding:0.75rem;background:var(--bg);border-radius:var(--radius);border:1px solid var(--border);">`;

      sig.certificateChain.forEach(cert => {
        const roles = {
          'root-ca': { icon: '🏛️', label: 'Root CA', color: '#4caf50' },
          'intermediate-ca': { icon: '🔗', label: 'Intermediate', color: '#2196f3' },
          'end-entity': { icon: '📄', label: 'End Entity', color: '#ff9800' }
        };
        const role = roles[cert.role] || { icon: '📄', label: 'Certificate', color: '#757575' };

        chainHtml += '<div style="margin-bottom:0.8rem;padding:0.6rem;background:var(--bg-secondary);border-radius:var(--radius);font-size:0.75rem;border-left:3px solid ' + role.color + ';">';
        chainHtml += `<div style="font-weight:600;color:${role.color};margin-bottom:0.4rem;font-size:0.8rem;">${role.icon} ${role.label} #${cert.position}</div>`;
        chainHtml += certRow('Subject', cert.subject);
        chainHtml += certRow('Issuer', cert.issuer);
        chainHtml += certRow('Serial', cert.serialNumber);
        chainHtml += certRow('Valid', `${cert.validFrom} to ${cert.validTo}`);
        chainHtml += certRow('Algorithm', `${cert.publicKeyAlgorithm} ${cert.keySize} bits`);
        chainHtml += '</div>';
      });

      chainHtml += `</div></div>`;
    }

    function certRow(label, value) {
      return `<div style="display:flex;justify-content:space-between;gap:0.5rem;padding:0.2rem 0;border-bottom:1px solid var(--border);"><div style="font-weight:500;color:var(--text-secondary);font-size:0.7rem;">${esc(label)}:</div><div style="color:var(--text);text-align:right;font-family:monospace;font-size:0.65rem;word-break:break-all;">${esc(value)}</div></div>`;
    }

    return (
      `<div class="signature-card" style="margin-bottom:1rem;padding:0.9rem;background:var(--bg-secondary);border-radius:var(--radius);border-left:4px solid ${bar};">` +
      `<div style="font-weight:700;color:${bar};margin-bottom:0.5rem;font-size:0.85rem;">${esc('Signature #' + (i + 1))}</div>` +
      `<div style="margin-bottom:0.5rem;">${chips}</div>` +
      `${detailRow('Signed By', sig.signedBy)}${detailRow('Organization', sig.organization)}${detailRow('Email', sig.email)}${detailRow('Signing Time', sig.signingTime)}${detailRow('Algorithm', sig.signatureAlgorithm)}${detailRow('Issuer', sig.certificateIssuer)}${detailRow('Valid From', sig.certificateValidFrom)}${detailRow('Valid To', sig.certificateValidTo)}${detailRow('Serial', sig.serialNumber)}` +
      `${chainHtml}</div>`
    );
  }).join('');
}

function chip(text, color) {
  return `<span style="display:inline-block;padding:2px 8px;border-radius:12px;background:${color}15;color:${color};font-size:0.7rem;font-weight:600;margin-right:6px;white-space:nowrap;">${text}</span>`;
}

function showLoading(text = 'Processing...') {
  const el = loading?.querySelector('.loading-text');
  if (el) el.textContent = text;
  loading?.classList.add('show');
}

function hideLoading() {
  loading?.classList.remove('show');
}

function hideResults() {
  results?.classList.remove('show');
}

function showError(message) {
  let html = `<div class="error-main">❌ ${esc(message)}</div>`;

  if (message.includes('timeout')) {
    html += `<div class="error-sub">⏱️ Verification timed out.</div>`;
    html += `<div class="error-help">💡 Try again or use Adobe Reader for advanced signatures.</div>`;
  } else if (message.includes('File too large')) {
    html += `<div class="error-sub">📁 File exceeds 6MB limit.</div>`;
  } else if (message.includes('Unsupported file type')) {
    html += `<div class="error-sub">📄 Only PDF, XML, P7M, P7S, SIG supported.</div>`;
  } else {
    html += `<div class="error-sub">🔍 For advanced signatures, try Adobe Reader.</div>`;
  }

  if (errorMessage) {
    errorMessage.innerHTML = html;
    errorMessage.className = 'error-message error show';
  }
}

function hideError() {
  errorMessage?.classList.remove('show');
}

function row(label, value, color = null) {
  const style = color ? ` style="color: ${color}; font-weight: 500;"` : '';
  return `<div class="detail-row"><div class="detail-label">${esc(label)}</div><div class="detail-value"${style}>${value}</div></div>`;
}

function esc(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text.toString();
  return div.innerHTML;
}
