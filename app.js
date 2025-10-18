// Signsley - Full App Wiring, Security-first Integrity, and Processing Pipeline
// v3.8 - Fixed Certificate Expiration vs Document Integrity

// DOM references
const uploadSection = document.getElementById('uploadSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetails = document.getElementById('resultDetails');
const errorMessage = document.getElementById('errorMessage');

document.addEventListener('DOMContentLoaded', () => { try { hideLoading(); hideError(); } catch (e) {} });

// Attach listeners if elements exist
if (fileInput) {
  fileInput.addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) handleFile(f);
  });
}

if (uploadSection) {
  uploadSection.addEventListener('click', (e) => {
    if (e.target && (e.target.id === 'browseBtn' || (e.target.closest && e.target.closest('#browseBtn')))) return;
    fileInput && fileInput.click();
  });

  ['dragenter','dragover'].forEach(evt => {
    uploadSection.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); uploadSection.classList.add('dragover'); });
  });
  ['dragleave','drop'].forEach(evt => {
    uploadSection.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); if (evt === 'drop') {
      const dt = e.dataTransfer; if (dt && dt.files && dt.files.length) { handleFile(dt.files[0]); }
    } uploadSection.classList.remove('dragover'); });
  });
}

if (browseBtn) {
  browseBtn.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); fileInput && fileInput.click(); });
}

// Processing pipeline
async function handleFile(file) {
  hideError();
  hideResults();
  try {
    validateFileSizeAndType(file);
    showLoading('Processing signature and validating certificates...');
    const arrayBuffer = await file.arrayBuffer();
    const base64Data = await arrayBufferToBase64(arrayBuffer);
    const endpoint = determineEndpointFromNameAndContent(file, arrayBuffer);
    const result = await sendVerificationRequest(endpoint, base64Data, file.name);
    hideLoading();
    displayResults(result);
  } catch (err) {
    console.error('Error:', err);
    hideLoading();
    showError(err.message || 'Verification failed');
  }
}

function validateFileSizeAndType(file) {
  const MAX_FILE_SIZE = 6 * 1024 * 1024;
  const SUPPORTED = ['pdf','xml','p7m','p7s','sig'];
  if (!file) throw new Error('No file selected');
  if (file.size === 0) throw new Error('File is empty');
  if (file.size > MAX_FILE_SIZE) throw new Error('File too large (max 6MB)');
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  if (!SUPPORTED.includes(ext)) throw new Error('Unsupported file type. Supported: PDF, XML, P7M, P7S, SIG');
}

function determineEndpointFromNameAndContent(file, arrayBuffer) {
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  if (ext === 'pdf') return '/.netlify/functions/verify-pades';
  if (ext === 'xml') return '/.netlify/functions/verify-xades';
  if (['p7m','p7s','sig'].includes(ext)) return '/.netlify/functions/verify-cades';
  const head = new Uint8Array(arrayBuffer.slice(0, 1024));
  const str = new TextDecoder('utf-8', { fatal: false }).decode(head);
  if (str.includes('%PDF')) return '/.netlify/functions/verify-pades';
  if (str.includes('<?xml') || str.includes('<')) return '/.netlify/functions/verify-xades';
  return '/.netlify/functions/verify-cades';
}

async function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    const sub = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    binary += String.fromCharCode.apply(null, sub);
    if (i % (chunk * 4) === 0) await new Promise(r => setTimeout(r, 0));
  }
  return btoa(binary);
}

async function sendVerificationRequest(endpoint, base64Data, fileName) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000);
  try {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileData: base64Data, fileName }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (!resp.ok) {
      const errData = await resp.json().catch(() => ({}));
      throw new Error(errData.error || `Server error: ${resp.status}`);
    }
    return await resp.json();
  } catch (e) {
    clearTimeout(timeoutId);
    if (e.name === 'AbortError') throw new Error('Request timeout - signature processing may require more time');
    throw e;
  }
}

// ================= FIXED: SECURITY-FIRST INTEGRITY =================
// CRITICAL FIX: Separate document integrity from certificate expiration
function determineFileIntegrityEnhanced(result) {
  // First check explicit document integrity markers
  if (typeof result.documentIntact === 'boolean') return result.documentIntact;
  if (result.fileName && result.fileName.toLowerCase().includes('tamper')) return false;
  
  // Check PDF-specific integrity markers
  if (result.format && result.format.includes('PAdES') && result.pdf) {
    if (typeof result.pdf.lastSignatureCoversAllContent === 'boolean') 
      return result.pdf.lastSignatureCoversAllContent;
    if (typeof result.pdf.incrementalUpdates === 'number' && result.pdf.incrementalUpdates > 2) 
      return false;
  }
  
  // Check cryptographic digest matches (independent of certificate status)
  if (typeof result.referenceDigestMatch === 'boolean') return result.referenceDigestMatch;
  if (typeof result.contentDigestMatch === 'boolean') return result.contentDigestMatch;
  
  // FIXED: Separate signature cryptographic validity from certificate trust
  const cryptoValid = result.cryptographicVerification === true;
  const sigValid = result.signatureValid === true;
  const structValid = result.structureValid === true;
  
  // Document integrity should NOT depend on certificate expiration or chain validity
  // Only check if signature was tampered with or structure is corrupted
  if (sigValid === false || structValid === false || result.revoked === true) return false;
  
  // If cryptographic verification passed, document is intact regardless of cert status
  if (cryptoValid && sigValid && structValid) return true;
  
  return null; // Unknown integrity - cannot determine definitively
}

// FIXED: Enhanced integrity status messages
function getIntegrityStatusMessage(integrityStatus, result) {
  if (integrityStatus === true) {
    return { 
      status: '✅ Document Intact', 
      detail: 'Cryptographic verification confirms document is unchanged since signing', 
      color: '#2c5f2d' 
    };
  }
  
  if (integrityStatus === false) {
    return { 
      status: '❌ Document Modified', 
      detail: 'Document content was altered after digital signature was applied', 
      color: '#c62828' 
    };
  }
  
  // Enhanced unknown status with specific reasons
  const reasons = [];
  if (result.cryptographicVerification !== true) reasons.push('cryptographic verification incomplete');
  if (result.signatureValid === null) reasons.push('signature validation inconclusive');
  if (!result.chainValidationPerformed) reasons.push('certificate chain not verified');
  
  // FIXED: Don't treat expired certificates as integrity issues
  if (result.certificateExpiredSinceSigning === true) {
    return { 
      status: '✅ Document Intact (Certificate Expired)', 
      detail: 'Document unchanged since signing, but certificate has expired since then', 
      color: '#f57c00' 
    };
  }
  
  const reasonText = reasons.length ? ` (${reasons.join(', ')})` : '';
  return { 
    status: '⚠️ Integrity Unknown', 
    detail: `Cannot definitively verify document integrity${reasonText}`, 
    color: '#f57c00' 
  };
}

// ================= FIXED: SIGNATURE STATUS =================
function determineSignatureStatusWithIntegrityOverride(result) {
  const integrity = determineFileIntegrityEnhanced(result);
  
  // Document modified - highest priority
  if (integrity === false) {
    return { 
      icon: '❌', 
      class: 'invalid', 
      title: 'Document Modified - Signatures Invalid', 
      description: 'Document was altered after signing, invalidating all signatures' 
    };
  }
  
  const multi = extractMultipleSignatureInfo(result);
  const multiFlag = multi.count > 1;
  const hasWarnings = result.warnings && result.warnings.filter(w => !w.toLowerCase().includes('multiple signatures detected')).length > 0;
  const isStructureOnly = !result.cryptographicVerification;
  
  const sigOK = result.signatureValid === true;
  const certValidAtSigning = result.certificateValidAtSigning !== false;
  const certExpiredSince = result.certificateExpiredSinceSigning === true;
  const chainOK = result.chainValid !== false;
  const revOK = !result.revoked;
  
  // FIXED: Separate expired certificates from invalid ones
  if (sigOK && certValidAtSigning && chainOK && revOK && certExpiredSince) {
    return { 
      icon: '⏰', 
      class: 'expired', 
      title: multiFlag ? 'Valid Signatures - Certificate Expired' : 'Valid Signature - Certificate Expired', 
      description: multiFlag ? 
        'Document integrity verified. Signatures were valid when created but certificates have since expired.' :
        'Document integrity verified. Signature was valid when created but certificate has since expired.' 
    };
  }
  
  // FIXED: Certificate was never valid (even at signing time)
  if (sigOK && !certValidAtSigning) {
    return { 
      icon: '❌', 
      class: 'invalid', 
      title: 'Invalid Certificate', 
      description: multiFlag ? 
        'Signatures are cryptographically valid but certificates were not valid at signing time' :
        'Signature is cryptographically valid but certificate was not valid at signing time' 
    };
  }
  
  // Document integrity unknown but signature structure exists
  if (integrity === null && sigOK) {
    return { 
      icon: '⚠️', 
      class: 'warning', 
      title: 'Signature Present - Integrity Unknown', 
      description: 'Cannot definitively verify document integrity due to incomplete validation data' 
    };
  }
  
  // Fallback to original logic for other cases
  const certOK = result.certificateValid;
  const certExp = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
  
  if (result.valid && sigOK && certOK && chainOK && revOK && !certExp) {
    const base = multiFlag ? 'Multiple Signatures Verified Successfully' : 'Signature Verified Successfully';
    return { icon: hasWarnings ? '⚠️' : '✅', class: hasWarnings ? 'warning' : 'valid', title: hasWarnings ? `${base} (with warnings)` : base, description: multiFlag ? `All ${multi.count} signatures are valid and current` : 'All signature components are valid and current' };
  }
  if (sigOK && certOK && chainOK && !revOK) return { icon: '🚫', class: 'invalid', title: 'Certificate Revoked', description: multiFlag ? 'Signatures are valid but one or more certificates have been revoked' : 'Signature is valid but certificate has been revoked' };
  if (sigOK && chainOK && certExp && !certExpiredSince) return { icon: '⏰', class: 'expired', title: multiFlag ? 'Valid Signatures - Certificate Expired' : 'Valid Signature - Certificate Expired', description: multiFlag ? 'Signatures were valid when created but one or more certificates have expired' : 'Signature was valid when created but certificate has expired' };
  if (sigOK && certOK && chainOK && revOK) return { icon: '✅', class: 'valid', title: multiFlag ? 'Multiple Signatures Verified Successfully' : 'Signature Verified Successfully', description: multiFlag ? `All ${multi.count} signature components are valid` : 'All signature components are valid' };
  if (result.structureValid && sigOK && certOK && chainOK) return { icon: '✅', class: 'valid', title: multiFlag ? 'Multiple Signatures Verified Successfully' : 'Signature Verified Successfully', description: multiFlag ? 'All signature structures and certificates are valid' : 'Signature structure and certificates are valid' };
  if (result.structureValid && isStructureOnly) return { icon: '📋', class: 'info', title: multiFlag ? 'Multiple Signature Structures Valid' : 'Signature Structure Valid', description: multiFlag ? 'Document contains multiple valid signature structures - cryptographic validation not performed' : 'Document structure verified - cryptographic validation not performed' };
  if (result.structureValid && !sigOK) return { icon: '❌', class: 'invalid', title: 'Invalid Signature', description: 'Signature cryptographic validation failed' };
  if (!result.structureValid) return { icon: '❌', class: 'invalid', title: 'Corrupted Signature Structure', description: 'Signature structure is damaged or invalid' };
  return { icon: '❌', class: 'invalid', title: 'No Valid Signature', description: 'No recognizable digital signature found' };
}

function extractMultipleSignatureInfo(result) {
  let count = 1;
  if (Array.isArray(result.signatures)) count = Math.max(count, result.signatures.length);
  if (Array.isArray(result.signatureDetails)) count = Math.max(count, result.signatureDetails.length);
  if (typeof result.signatureCount === 'number') count = Math.max(count, result.signatureCount);
  if (result.warnings) {
    for (const w of result.warnings) {
      const m = w.match(/Multiple signatures detected\s*\((\d+)\)/i);
      if (m) { count = Math.max(count, parseInt(m[1])); break; }
    }
  }
  return { count };
}

function displayResults(result) {
  if (!result) { showError('Invalid result'); return; }
  const integrity = determineFileIntegrityEnhanced(result);
  const integrityMsg = getIntegrityStatusMessage(integrity, result);
  const main = integrity === false ? { icon: '❌', class: 'invalid', title: 'Document Modified - Signatures Invalid', description: 'Document was altered after signing, invalidating all signatures' } : determineSignatureStatusWithIntegrityOverride(result);
  resultIcon.textContent = main.icon;
  resultIcon.className = 'result-icon ' + main.class;
  resultTitle.textContent = main.title;
  let html = '';
  html += `<div class="integrity-section" style="margin-bottom:1.5rem;padding:1rem;background:var(--bg-secondary);border-radius:8px;border-left:4px solid ${integrityMsg.color};">`;
  html += `<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.5rem;">🛡️ File Integrity Status</div>`;
  html += `<div style="color:${integrityMsg.color};font-weight:500;">${integrityMsg.status}</div>`;
  html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">${esc(integrityMsg.detail)}</div>`;
  html += `</div>`;
  const multi = extractMultipleSignatureInfo(result);
  if (multi.count > 1) {
    html += '<div class="signature-info-section" style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid #2c5f2d;">';
    html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem;">📝 Signature Information</div>';
    html += '<div style="color: #2c5f2d; font-weight: 500;">✅ Multiple Signatures Detected</div>';
    html += `<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Document contains ${multi.count} valid digital signatures</div>`;
    html += '</div>';
  }
  const sigs = getSignaturesArray(result);
  if (sigs.length > 0) {
    html += renderSignatureCards(sigs, integrity);
  }
  if (result.error) {
    html += row('Status', esc(result.error), !result.cryptographicVerification ? '#2196f3' : '#f57c00');
  }
  html += row('File', esc(result.fileName));
  html += row('Format', esc(result.format));
  if (result.processingTime) html += row('Processing', `${result.processingTime}ms`);
  if (result.cryptographicVerification !== undefined) {
    const st = result.cryptographicVerification ? '✅ Full Verification' : '📋 Structure Analysis';
    const col = result.cryptographicVerification ? '#2c5f2d' : '#2196f3';
    html += row('Verification', st, col);
  }
  if (result.structureValid !== undefined) html += row('Structure', result.structureValid ? '✅ Valid' : '❌ Invalid', result.structureValid ? '#2c5f2d' : '#c62828');
  if (result.certificateValid !== undefined) {
    const certExp = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
    let txt, col; if (result.certificateValid && !certExp) { txt='✅ Valid'; col='#2c5f2d'; } else if (result.certificateValid && certExp) { txt='⏰ Valid but Expired'; col='#f57c00'; } else if (!result.certificateValid && certExp) { txt='❌ Invalid & Expired'; col='#c62828'; } else { txt='❌ Invalid'; col='#c62828'; }
    html += row('Certificate', txt, col);
  }
  if (result.chainValidationPerformed !== undefined) html += row('Chain Validation', result.chainValid ? '✅ Valid Chain' : '⚠️ Chain Issues', result.chainValid ? '#2c5f2d' : '#f57c00');
  if (result.revocationChecked !== undefined) {
    let txt, col; if (result.revocationChecked) { if (result.revoked) { txt='🚫 Certificate Revoked'; col='#c62828'; } else { txt='✅ Not Revoked'; col='#2c5f2d'; } } else { txt='⚠️ Not Checked'; col='#f57c00'; }
    html += row('Revocation Status', txt, col);
  }
  add('Detection Method', result.detectionMethod);
  add('Details', result.details);
  if (result.troubleshooting && result.troubleshooting.length > 0) {
    const tips = result.troubleshooting.map(t => `💡 ${esc(t)}`).join('<br>');
    html += row('Recommendations', tips, '#2196f3');
  }
  if (result.certificateChain && result.certificateChain.length > 0) {
    html += '<div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 2px solid var(--border);"></div>';
    html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.75rem;">🔗 Certificate Chain Details</div>';
    result.certificateChain.forEach(cert => {
      const roles = { 'root-ca': { icon: '🏛️', label: 'Root CA', color: '#4caf50' }, 'intermediate-ca': { icon: '🔗', label: 'Intermediate CA', color: '#2196f3' }, 'end-entity': { icon: '📄', label: 'End Entity', color: '#ff9800' } };
      const role = roles[cert.role] || { icon: '📄', label: 'Certificate', color: '#757575' };
      html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 8px; font-size: 0.8125rem; border-left: 4px solid ' + role.color + ';">';
      html += `<div style=\"font-weight: 600; color: ${role.color}; margin-bottom: 0.5rem;\">${role.icon} ${role.label} #${cert.position}</div>`;
      html += certRow('Subject', cert.subject);
      html += certRow('Issuer', cert.issuer);
      html += certRow('Serial', cert.serialNumber);
      html += certRow('Valid From', cert.validFrom);
      html += certRow('Valid To', cert.validTo);
      html += certRow('Key Algorithm', cert.publicKeyAlgorithm);
      html += certRow('Key Size', cert.keySize + ' bits');
      const ssCol = cert.isSelfSigned ? '#f57c00' : '#2c5f2d';
      const ssIcon = cert.isSelfSigned ? '⚠️' : '✅';
      html += `<div style=\"display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;\">`+
              `<div style=\"font-weight: 500; color: var(--text-secondary);\">Self-Signed:</div>`+
              `<div style=\"color: ${ssCol}; word-break: break-word;\">${ssIcon} ${cert.isSelfSigned ? 'Yes' : 'No'}</div>`+
              `</div>`;
      html += '</div>';
    });
  }
  function certRow(label, value) { return `<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;">`+`<div style="font-weight: 500; color: var(--text-secondary);">${esc(label)}:</div>`+`<div style="color: var(--text); word-break: break-word; font-family: monospace; font-size: 0.9em;">${esc(value)}</div>`+`</div>`; }
  function add(label, value) { if (value && value !== 'Unknown') html += row(label, esc(value)); }
  resultDetails.innerHTML = html;
  results.classList.add('show');
}

function getSignaturesArray(result) {
  if (Array.isArray(result.signatures) && result.signatures.length > 0) return result.signatures;
  if (Array.isArray(result.signatureDetails) && result.signatureDetails.length > 0) return result.signatureDetails;
  if (Array.isArray(result.signers) && result.signers.length > 0) return result.signers;
  const f = { signatureValid: result.signatureValid, structureValid: result.structureValid, certificateValid: result.certificateValid, chainValid: result.chainValid, chainValidationPerformed: result.chainValidationPerformed, revocationChecked: result.revocationChecked, revoked: result.revoked, signedBy: result.signedBy, organization: result.organization, email: result.email, signingTime: result.signatureDate || result.signingTime, signatureAlgorithm: result.signatureAlgorithm, certificateIssuer: result.certificateIssuer, certificateValidFrom: result.certificateValidFrom, certificateValidTo: result.certificateValidTo, serialNumber: result.serialNumber, isSelfSigned: result.isSelfSigned };
  const any = Object.values(f).some(v => v !== undefined && v !== null && v !== 'Unknown');
  return any ? [f] : [];
}

function renderSignatureCards(signatures, integrity) {
  if (!Array.isArray(signatures) || signatures.length === 0) return '';
  return signatures.map((sig, i) => {
    const forcedInvalid = integrity === false;
    const ok = !forcedInvalid && sig.signatureValid === true && sig.certificateValid !== false && sig.chainValid !== false && sig.revoked !== true;
    const bar = forcedInvalid ? '#c62828' : (ok ? '#2c5f2d' : (sig.signatureValid === false ? '#c62828' : '#f57c00'));
    let chips = '';
    if (forcedInvalid) {
      chips += chip('Signature: Invalid (Document Modified)', '#c62828');
      chips += chip('Integrity: Failed', '#c62828');
    } else {
      chips += chip(sig.signatureValid === true ? 'Signature: Valid' : (sig.signatureValid === false ? 'Signature: Invalid' : 'Signature: Unknown'), sig.signatureValid === true ? '#2c5f2d' : (sig.signatureValid === false ? '#c62828' : '#f57c00'));
      if (sig.structureValid !== undefined) chips += chip(sig.structureValid ? 'Structure: OK' : 'Structure: Bad', sig.structureValid ? '#2c5f2d' : '#c62828');
      let certColor = '#2c5f2d', certText = 'Certificate: Valid';
      const exp = (sig.certificateValidTo && new Date(sig.certificateValidTo) < new Date());
      if (sig.certificateValid === false && exp) { certText = 'Certificate: Invalid & Expired'; certColor = '#c62828'; }
      else if (sig.certificateValid === true && exp) { certText = 'Certificate: Valid but Expired'; certColor = '#f57c00'; }
      else if (sig.certificateValid === false) { certText = 'Certificate: Invalid'; certColor = '#c62828'; }
      else if (exp) { certText = 'Certificate: Expired'; certColor = '#f57c00'; }
      chips += chip(certText, certColor);
      if (sig.chainValidationPerformed !== undefined) chips += chip(sig.chainValid ? 'Chain: OK' : 'Chain: Issues', sig.chainValid ? '#2c5f2d' : '#f57c00');
      if (sig.revocationChecked !== undefined) {
        if (sig.revocationChecked && sig.revoked === true) chips += chip('Revocation: Revoked', '#c62828');
        else if (sig.revocationChecked && sig.revoked === false) chips += chip('Revocation: Not Revoked', '#2c5f2d');
        else chips += chip('Revocation: Not Checked', '#f57c00');
      }
    }
    const row = (l, v) => { if (!v && v !== 0) return ''; return `<div style=\"display:grid;grid-template-columns:130px 1fr;gap:0.5rem;padding:0.25rem 0;border-bottom:1px solid var(--border);line-height:1.4;\"><div style=\"font-weight:500;color:var(--text-secondary);\">${esc(l)}:</div><div style=\"color:var(--text);word-break:break-word;\">${esc(String(v))}</div></div>`; };
    return `<div style="margin-bottom:1rem;padding:0.9rem;background:var(--bg-secondary);border-radius:10px;border-left:4px solid ${bar};"><div style="font-weight:700;color:${bar};margin-bottom:0.5rem;">${esc('Signature #'+(i+1))}</div><div style="margin-bottom:0.5rem;">${chips}</div>${row('Signed By',sig.signedBy)}${row('Organization',sig.organization)}${row('Email',sig.email)}${row('Signing Time',sig.signingTime)}${row('Algorithm',sig.signatureAlgorithm)}${row('Issuer',sig.certificateIssuer)}${row('Valid From',sig.certificateValidFrom)}${row('Valid To',sig.certificateValidTo)}${row('Serial',sig.serialNumber)}${sig.isSelfSigned!==undefined?row('Self-Signed', yesNo(sig.isSelfSigned)):''}</div>`;
  }).join('');
}

function yesNo(v){ if (v === true) return '✅ Yes'; if (v === false) return '❌ No'; return '⚠️ Unknown'; }
function chip(text,color){ return `<span style="display:inline-block;padding:2px 8px;border-radius:12px;background:${color}15;color:${color};font-size:0.75rem;font-weight:600;margin-right:6px;">${text}</span>`; }

// UI helpers
function showLoading(text = 'Processing...') { const el = loading && loading.querySelector('.loading-text'); if (el) { el.textContent = text; let dots = 0; const it = setInterval(() => { if (!loading.classList.contains('show')) { clearInterval(it); return; } dots = (dots + 1) % 4; el.textContent = text + '.'.repeat(dots); }, 500);} loading && loading.classList.add('show'); }
function hideLoading() { loading && loading.classList.remove('show'); }
function hideResults() { results && results.classList.remove('show'); }
function showError(message) { let html = `<div class="error-main">❌ ${esc(message)}</div>`; if (message.includes('timeout')) { html += `<div class="error-sub">⏱️ The signature verification process timed out.</div>`; html += `<div class="error-help">💡 Try again, or use Adobe Acrobat Reader for advanced signatures.</div>`; } else if (message.includes('File too large')) { html += `<div class="error-sub">📁 The file exceeds the maximum size limit of 6MB.</div>`; html += `<div class="error-help">💡 Try compressing the PDF or use a smaller file.</div>`; } else if (message.includes('Unsupported file type')) { html += `<div class="error-sub">📄 Only PDF, XML, P7M, P7S, and SIG files are supported.</div>`; html += `<div class="error-help">💡 Ensure your file has the correct extension and format.</div>`; } else { html += `<div class="error-sub">🔍 For advanced signatures, try Adobe Acrobat Reader for full verification.</div>`; html += `<div class="error-help">💡 If the problem persists, the signature may use proprietary encoding.</div>`; } if (errorMessage) { errorMessage.innerHTML = html; errorMessage.className = 'error-message error show'; } }
function hideError() { errorMessage && errorMessage.classList.remove('show'); }
function row(label, value, color = null) { const style = color ? ` style=\"color: ${color}; font-weight: 500;\"` : ''; return `<div class=\"detail-row\"><div class=\"detail-label\">${esc(label)}:</div><div class=\"detail-value\"${style}>${value}</div></div>`; }
function esc(text) { if (!text) return ''; const div = document.createElement('div'); div.textContent = text.toString(); return div.innerHTML; }

console.log('Signsley - v3.8 Fixed Certificate Expiration vs Document Integrity');