// Signsley - Enhanced Version with File Integrity, Multiple Signatures Sections, and Improved Status & Integrity Logic

const uploadSection = document.getElementById('uploadSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetails = document.getElementById('resultDetails');
const errorMessage = document.getElementById('errorMessage');

document.addEventListener('DOMContentLoaded', () => {
    try { hideLoading(); hideError(); } catch (e) {}
});

const CONFIG = {
    MAX_FILE_SIZE: 6 * 1024 * 1024,
    REQUEST_TIMEOUT: 120000,
    SUPPORTED_EXTENSIONS: ['pdf', 'xml', 'p7m', 'p7s', 'sig']
};

function validateFile(file) {
    if (!file) throw new Error('No file selected');
    if (file.size === 0) throw new Error('File is empty');
    if (file.size > CONFIG.MAX_FILE_SIZE) throw new Error('File too large (max 6MB)');

    const ext = file.name.split('.').pop().toLowerCase();
    if (!CONFIG.SUPPORTED_EXTENSIONS.includes(ext)) {
        throw new Error('Unsupported file type. Supported: PDF, XML, P7M, P7S, SIG');
    }
    return true;
}

// Event listeners
uploadSection.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadSection.classList.add('dragover');
});

uploadSection.addEventListener('dragleave', (e) => {
    e.preventDefault();
    uploadSection.classList.remove('dragover');
});

uploadSection.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadSection.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
    }
});

uploadSection.addEventListener('click', () => fileInput.click());
browseBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

async function handleFile(file) {
    hideError();
    hideResults();

    try {
        validateFile(file);
        showLoading('Processing signature and validating certificates...');

        const arrayBuffer = await fileToArrayBuffer(file);
        const base64Data = await arrayBufferToBase64(arrayBuffer);
        const endpoint = determineEndpoint(file, arrayBuffer);

        const result = await sendVerificationRequest(endpoint, base64Data, file.name);

        hideLoading();
        displayResults(result);

    } catch (error) {
        console.error('Error:', error);
        hideLoading();
        showError(error.message || 'Verification failed');
    }
}

function fileToArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsArrayBuffer(file);
    });
}

async function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
        binary += String.fromCharCode.apply(null, chunk);
        if (i % (chunkSize * 4) === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }

    return btoa(binary);
}

function determineEndpoint(file, arrayBuffer) {
    const ext = file.name.split('.').pop().toLowerCase();

    if (ext === 'pdf') return '/.netlify/functions/verify-pades';
    if (ext === 'xml') return '/.netlify/functions/verify-xades';
    if (['p7m', 'p7s', 'sig'].includes(ext)) return '/.netlify/functions/verify-cades';

    const uint8 = new Uint8Array(arrayBuffer.slice(0, 1000));
    const str = new TextDecoder('utf-8', { fatal: false }).decode(uint8);

    if (str.includes('%PDF')) return '/.netlify/functions/verify-pades';
    if (str.includes('<?xml') || str.includes('<')) return '/.netlify/functions/verify-xades';
    return '/.netlify/functions/verify-cades';
}

async function sendVerificationRequest(endpoint, base64Data, fileName) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fileData: base64Data, fileName: fileName }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }

        return await response.json();

    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('Request timeout - signature processing may require more time');
        }
        throw error;
    }
}

// Strict integrity determination with safe fallbacks
function determineFileIntegrity(result) {
    // Backend authoritative verdict
    if (typeof result.documentIntact === 'boolean') return result.documentIntact;

    // PAdES hints
    if (result.pdf) {
        if (typeof result.pdf.lastSignatureCoversAllContent === 'boolean') {
            return result.pdf.lastSignatureCoversAllContent;
        }
        // If backend reports incrementalUpdates but also says structureValid && signatureValid && chainValid && revocation ok, 
        // prefer "true" (intact) for standard multi-sign PDF flows that add signature revisions without content changes.
        if (typeof result.pdf.incrementalUpdates === 'number') {
            const allOk = result.signatureValid === true && result.structureValid === true && result.chainValid !== false && result.revoked !== true;
            if (allOk && result.pdf.incrementalUpdates >= 1 && result.pdf.lastSignatureCoversAllContent !== false) {
                return true; // treat as intact when revisions are signature-related only
            }
            return null; // unknown otherwise
        }
    }

    // XAdES/CAdES hints
    if (typeof result.referenceDigestMatch === 'boolean') return result.referenceDigestMatch;
    if (typeof result.contentDigestMatch === 'boolean') return result.contentDigestMatch;

    // Conservative default: unknown
    return null;
}

function getSignaturesArray(result) {
    if (Array.isArray(result.signatures) && result.signatures.length > 0) {
        return result.signatures;
    }
    // Try to split by backend-provided signatureDetails list if available
    if (Array.isArray(result.signatureDetails) && result.signatureDetails.length > 0) {
        return result.signatureDetails;
    }
    const fallback = {
        signatureValid: result.signatureValid,
        structureValid: result.structureValid,
        certificateValid: result.certificateValid,
        chainValid: result.chainValid,
        chainValidationPerformed: result.chainValidationPerformed,
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
        isSelfSigned: result.isSelfSigned
    };
    const anyValue = Object.values(fallback).some(v => v !== undefined && v !== null && v !== 'Unknown');
    return anyValue ? [fallback] : [];
}

function chip(text, color) {
  return `<span style="display:inline-block;padding:2px 8px;border-radius:12px;background:${color}15;color:${color};font-size:0.75rem;font-weight:600;margin-right:6px;">${text}</span>`;
}

function yesNo(val) {
  if (val === true) return '✅ Yes';
  if (val === false) return '❌ No';
  return '⚠️ Unknown';
}

function renderSignatureCards(signatures) {
  if (!Array.isArray(signatures) || signatures.length === 0) return '';

  return signatures.map((sig, idx) => {
    const title = `Signature #${idx + 1}`;
    const ok = sig.signatureValid === true && sig.certificateValid !== false && sig.chainValid !== false && sig.revoked !== true;
    const barColor = ok ? '#2c5f2d' : (sig.signatureValid === false ? '#c62828' : '#f57c00');

    let statusChips = '';
    statusChips += chip(sig.signatureValid === true ? 'Signature: Valid' : (sig.signatureValid === false ? 'Signature: Invalid' : 'Signature: Unknown'), sig.signatureValid === true ? '#2c5f2d' : (sig.signatureValid === false ? '#c62828' : '#f57c00'));
    if (sig.structureValid !== undefined) statusChips += chip(sig.structureValid ? 'Structure: OK' : 'Structure: Bad', sig.structureValid ? '#2c5f2d' : '#c62828');

    let certChipColor = '#2c5f2d';
    let certChipText = 'Certificate: Valid';
    const certExpired = (sig.certificateValidTo && new Date(sig.certificateValidTo) < new Date());
    if (sig.certificateValid === false && certExpired) { certChipText = 'Certificate: Invalid & Expired'; certChipColor = '#c62828'; }
    else if (sig.certificateValid === true && certExpired) { certChipText = 'Certificate: Valid but Expired'; certChipColor = '#f57c00'; }
    else if (sig.certificateValid === false) { certChipText = 'Certificate: Invalid'; certChipColor = '#c62828'; }
    else if (certExpired) { certChipText = 'Certificate: Expired'; certChipColor = '#f57c00'; }
    statusChips += chip(certChipText, certChipColor);

    if (sig.chainValidationPerformed !== undefined) {
      statusChips += chip(sig.chainValid ? 'Chain: OK' : 'Chain: Issues', sig.chainValid ? '#2c5f2d' : '#f57c00');
    }
    if (sig.revocationChecked !== undefined) {
      if (sig.revocationChecked && sig.revoked === true) { statusChips += chip('Revocation: Revoked', '#c62828'); }
      else if (sig.revocationChecked && sig.revoked === false) { statusChips += chip('Revocation: Not Revoked', '#2c5f2d'); }
      else { statusChips += chip('Revocation: Not Checked', '#f57c00'); }
    }

    const gridRow = (label, value) => {
      if (!value && value !== 0) return '';
      return `<div style=\"display:grid;grid-template-columns:130px 1fr;gap:0.5rem;padding:0.25rem 0;border-bottom:1px solid var(--border);line-height:1.4;\">`+
        `<div style=\"font-weight:500;color:var(--text-secondary);\">${esc(label)}:</div>`+
        `<div style=\"color:var(--text);word-break:break-word;\">${esc(String(value))}</div>`+
      `</div>`;
    };

    const section =
      `<div style="margin-bottom:1rem;padding:0.9rem;background:var(--bg-secondary);border-radius:10px;border-left:4px solid ${barColor};">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
          <div style="font-weight:700;color:${barColor};">${esc(title)}</div>
        </div>
        <div style="margin-bottom:0.5rem;">${statusChips}</div>
        ${gridRow('Signed By', sig.signedBy)}
        ${gridRow('Organization', sig.organization)}
        ${gridRow('Email', sig.email)}
        ${gridRow('Signing Time', sig.signingTime)}
        ${gridRow('Algorithm', sig.signatureAlgorithm)}
        ${gridRow('Issuer', sig.certificateIssuer)}
        ${gridRow('Valid From', sig.certificateValidFrom)}
        ${gridRow('Valid To', sig.certificateValidTo)}
        ${gridRow('Serial', sig.serialNumber)}
        ${sig.isSelfSigned !== undefined ? gridRow('Self-Signed', yesNo(sig.isSelfSigned)) : ''}
      </div>`;

    return section;
  }).join('');
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

function determineSignatureStatusEnhanced(result) {
    const integrity = determineFileIntegrity(result);
    if (integrity === false) {
      return {
        icon: '❌',
        class: 'invalid',
        title: 'Document Modified After Signing',
        description: 'Changes were detected after the last signature; verification fails'
      };
    }

    const multipleSignatures = extractMultipleSignatureInfo(result);
    const hasMultipleSignatures = multipleSignatures.count > 1;
    
    const hasWarnings = result.warnings && result.warnings.filter(w => 
        !w.toLowerCase().includes('multiple signatures detected')
    ).length > 0;
    
    const isStructureOnly = !result.cryptographicVerification;
    const chainValid = result.chainValid;
    const revocationOk = !result.revoked;
    const certValid = result.certificateValid;
    const sigValid = result.signatureValid;
    const certExpired = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());

    if (result.valid && sigValid && certValid && chainValid && revocationOk && !certExpired) {
        const baseTitle = hasMultipleSignatures ? 'Multiple Signatures Verified Successfully' : 'Signature Verified Successfully';
        return {
            icon: hasWarnings ? '⚠️' : '✅',
            class: hasWarnings ? 'warning' : 'valid',
            title: hasWarnings ? `${baseTitle} (with warnings)` : baseTitle,
            description: hasMultipleSignatures 
                ? `All ${multipleSignatures.count} signatures are valid and current`
                : 'All signature components are valid and current'
        };
    } else if (sigValid && certValid && chainValid && !revocationOk) {
        return {
            icon: '🚫',
            class: 'invalid',
            title: 'Certificate Revoked',
            description: hasMultipleSignatures 
                ? 'Signatures are valid but one or more certificates have been revoked'
                : 'Signature is valid but certificate has been revoked'
        };
    } else if (sigValid && chainValid && certExpired) {
        return {
            icon: '⏰',
            class: 'expired',
            title: hasMultipleSignatures ? 'Valid Signatures - Certificate Expired' : 'Valid Signature - Certificate Expired',
            description: hasMultipleSignatures 
                ? 'Signatures were valid when created but one or more certificates have expired'
                : 'Signature was valid when created but certificate has expired'
        };
    } else if (sigValid && certValid && chainValid && revocationOk) {
        return {
            icon: '✅',
            class: 'valid',
            title: hasMultipleSignatures ? 'Multiple Signatures Verified Successfully' : 'Signature Verified Successfully',
            description: hasMultipleSignatures 
                ? `All ${multipleSignatures.count} signature components are valid`
                : 'All signature components are valid'
        };
    } else if (result.structureValid && sigValid && certValid && chainValid) {
        return {
            icon: '✅',
            class: 'valid',
            title: hasMultipleSignatures ? 'Multiple Signatures Verified Successfully' : 'Signature Verified Successfully',
            description: hasMultipleSignatures 
                ? 'All signature structures and certificates are valid'
                : 'Signature structure and certificates are valid'
        };
    } else if (result.structureValid && isStructureOnly) {
        return {
            icon: '📋',
            class: 'info',
            title: hasMultipleSignatures ? 'Multiple Signature Structures Valid' : 'Signature Structure Valid',
            description: hasMultipleSignatures 
                ? 'Document contains multiple valid signature structures - cryptographic validation not performed'
                : 'Document structure verified - cryptographic validation not performed'
        };
    } else if (result.structureValid && !sigValid) {
        return {
            icon: '❌',
            class: 'invalid',
            title: 'Invalid Signature',
            description: 'Signature cryptographic validation failed'
        };
    } else if (!result.structureValid) {
        return {
            icon: '❌',
            class: 'invalid',
            title: 'Corrupted Signature Structure',
            description: 'Signature structure is damaged or invalid'
        };
    } else {
        return {
            icon: '❌',
            class: 'invalid',
            title: 'No Valid Signature',
            description: 'No recognizable digital signature found'
        };
    }
}

function displayResults(result) {
    if (!result) {
        showError('Invalid result');
        return;
    }

    const integrityStatus = determineFileIntegrity(result);
    const signatureStatus = determineSignatureStatusEnhanced(result);

    resultIcon.textContent = signatureStatus.icon;
    resultIcon.className = 'result-icon ' + signatureStatus.class;
    resultTitle.textContent = signatureStatus.title;

    let html = '';

    html += '<div class="integrity-section" style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid ' + getIntegrityColor(integrityStatus) + ';">';
    html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem;">🛡️ File Integrity Status</div>';
    if (integrityStatus === true) {
        html += '<div style="color: #2c5f2d; font-weight: 500;">✅ Document Intact</div>';
        html += '<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">The file has not been modified after signing</div>';
    } else if (integrityStatus === false) {
        html += '<div style="color: #c62828; font-weight: 500;">❌ Document Modified</div>';
        if (result.integrityReason) {
            html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">${esc(result.integrityReason)}</div>`;
        }
        if (result.pdf && typeof result.pdf.incrementalUpdates === 'number') {
            html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">PDF incremental updates: ${result.pdf.incrementalUpdates}</div>`;
        }
    } else {
        html += '<div style="color: #f57c00; font-weight: 500;">⚠️ Integrity Unknown</div>';
        if (result.pdf && typeof result.pdf.incrementalUpdates === 'number') {
            html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">PDF incremental updates: ${result.pdf.incrementalUpdates}</div>`;
        }
    }
    html += '</div>';

    const multipleSignatures = extractMultipleSignatureInfo(result);
    if (multipleSignatures.count > 1) {
        html += '<div class="signature-info-section" style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid #2c5f2d;">';
        html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem;">📝 Signature Information</div>';
        html += '<div style="color: #2c5f2d; font-weight: 500;">✅ Multiple Signatures Detected</div>';
        html += `<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Document contains ${multipleSignatures.count} valid digital signatures</div>`;
        html += '</div>';
    }

    const signatures = getSignaturesArray(result);
    if (signatures.length > 0) {
        html += renderSignatureCards(signatures);
    }

    if (result.error) {
        html += row('Status', esc(result.error), !result.cryptographicVerification ? '#2196f3' : '#f57c00');
    }

    html += row('File', esc(result.fileName));
    html += row('Format', esc(result.format));

    if (result.processingTime) {
        html += row('Processing', `${result.processingTime}ms`);
    }

    if (result.cryptographicVerification !== undefined) {
        const status = result.cryptographicVerification ? '✅ Full Verification' : '📋 Structure Analysis';
        const color = result.cryptographicVerification ? '#2c5f2d' : '#2196f3';
        html += row('Verification', status, color);
    }

    if (result.structureValid !== undefined) {
        html += row('Structure', result.structureValid ? '✅ Valid' : '❌ Invalid', result.structureValid ? '#2c5f2d' : '#c62828');
    }

    if (result.certificateValid !== undefined) {
        const certExpired = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
        let certStatus, certColor;
        if (result.certificateValid && !certExpired) { certStatus = '✅ Valid'; certColor = '#2c5f2d'; }
        else if (result.certificateValid && certExpired) { certStatus = '⏰ Valid but Expired'; certColor = '#f57c00'; }
        else if (!result.certificateValid && certExpired) { certStatus = '❌ Invalid & Expired'; certColor = '#c62828'; }
        else { certStatus = '❌ Invalid'; certColor = '#c62828'; }
        html += row('Certificate', certStatus, certColor);
    }

    if (result.chainValidationPerformed !== undefined) {
        html += row('Chain Validation', result.chainValid ? '✅ Valid Chain' : '⚠️ Chain Issues', result.chainValid ? '#2c5f2d' : '#f57c00');
    }

    if (result.revocationChecked !== undefined) {
        let revocationStatus, revocationColor;
        if (result.revocationChecked) {
            if (result.revoked) { revocationStatus = '🚫 Certificate Revoked'; revocationColor = '#c62828'; }
            else { revocationStatus = '✅ Not Revoked'; revocationColor = '#2c5f2d'; }
        } else { revocationStatus = '⚠️ Not Checked'; revocationColor = '#f57c00'; }
        html += row('Revocation Status', revocationStatus, revocationColor);
    }

    add('Detection Method', result.detectionMethod);
    add('Details', result.details);

    if (result.troubleshooting && result.troubleshooting.length > 0) {
        const troubleshootingHtml = result.troubleshooting.map(t => `💡 ${esc(t)}`).join('<br>');
        html += row('Recommendations', troubleshootingHtml, '#2196f3');
    }

    if (result.certificateChain && result.certificateChain.length > 0) {
        html += '<div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 2px solid var(--border);"></div>';
        html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.75rem;">🔗 Certificate Chain Details</div>';
        result.certificateChain.forEach((cert) => {
            const roleData = {
                'root-ca': { icon: '🏛️', label: 'Root CA', color: '#4caf50' },
                'intermediate-ca': { icon: '🔗', label: 'Intermediate CA', color: '#2196f3' },
                'end-entity': { icon: '📄', label: 'End Entity', color: '#ff9800' }
            };
            const role = roleData[cert.role] || { icon: '📄', label: 'Certificate', color: '#757575' };
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 8px; font-size: 0.8125rem; border-left: 4px solid ' + role.color + ';">';
            html += `<div style=\"font-weight: 600; color: ${role.color}; margin-bottom: 0.5rem;\">${role.icon} ${role.label} #${cert.position}</div>`;
            html += certRow('Subject', cert.subject);
            html += certRow('Issuer', cert.issuer);
            html += certRow('Serial', cert.serialNumber);
            html += certRow('Valid From', cert.validFrom);
            html += certRow('Valid To', cert.validTo);
            html += certRow('Key Algorithm', cert.publicKeyAlgorithm);
            html += certRow('Key Size', cert.keySize + ' bits');
            const selfSignedColor = cert.isSelfSigned ? '#f57c00' : '#2c5f2d';
            const selfSignedIcon = cert.isSelfSigned ? '⚠️' : '✅';
            html += `<div style=\"display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;\">`+
                    `<div style=\"font-weight: 500; color: var(--text-secondary);\">Self-Signed:</div>`+
                    `<div style=\"color: ${selfSignedColor}; word-break: break-word;\">${selfSignedIcon} ${cert.isSelfSigned ? 'Yes' : 'No'}</div>`+
                    `</div>`;
            html += '</div>';
        });
    }

    function certRow(label, value) {
        return `<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;">`+
               `<div style="font-weight: 500; color: var(--text-secondary);">${esc(label)}:</div>`+
               `<div style="color: var(--text); word-break: break-word; font-family: monospace; font-size: 0.9em;">${esc(value)}</div>`+
               `</div>`;
    }

    function add(label, value) {
        if (value && value !== 'Unknown') {
            html += row(label, esc(value));
        }
    }

    resultDetails.innerHTML = html;
    results.classList.add('show');
}

function getIntegrityColor(integrityStatus) {
    if (integrityStatus === true) return '#2c5f2d';
    if (integrityStatus === false) return '#c62828';
    return '#f57c00';
}

function row(label, value, color = null) {
    const style = color ? ` style="color: ${color}; font-weight: 500;"` : '';
    return `<div class="detail-row"><div class="detail-label">${esc(label)}:</div><div class="detail-value"${style}>${value}</div></div>`;
}

function esc(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text.toString();
    return div.innerHTML;
}

function showLoading(text = 'Processing...') {
    const el = loading.querySelector('.loading-text');
    if (el) {
        el.textContent = text;
        let dots = 0;
        const interval = setInterval(() => {
            if (!loading.classList.contains('show')) {
                clearInterval(interval);
                return;
            }
            dots = (dots + 1) % 4;
            el.textContent = text + '.'.repeat(dots);
        }, 500);
    }
    loading.classList.add('show');
}

function hideLoading() {
    loading.classList.remove('show');
}

function hideResults() {
    results.classList.remove('show');
}

function showError(message) {
    let errorHtml = `<div class="error-main">❌ ${esc(message)}</div>`;

    if (message.includes('timeout')) {
        errorHtml += `<div class="error-sub">⏱️ The signature verification process timed out.</div>`;
        errorHtml += `<div class="error-help">💡 Try again, or use Adobe Acrobat Reader for advanced signatures.</div>`;
    } else if (message.includes('File too large')) {
        errorHtml += `<div class="error-sub">📁 The file exceeds the maximum size limit of 6MB.</div>`;
        errorHtml += `<div class="error-help">💡 Try compressing the PDF or use a smaller file.</div>`;
    } else if (message.includes('Unsupported file type')) {
        errorHtml += `<div class="error-sub">📄 Only PDF, XML, P7M, P7S, and SIG files are supported.</div>`;
        errorHtml += `<div class="error-help">💡 Ensure your file has the correct extension and format.</div>`;
    } else {
        errorHtml += `<div class="error-sub">🔍 For advanced signatures, try Adobe Acrobat Reader for full verification.</div>`;
        errorHtml += `<div class="error-help">💡 If the problem persists, the signature may use proprietary encoding.</div>`;
    }

    errorMessage.innerHTML = errorHtml;
    errorMessage.className = 'error-message error show';
}

function hideError() {
    errorMessage.classList.remove('show');
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideError();
        hideResults();
    } else if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        fileInput.click();
    }
});

document.addEventListener('dragenter', (e) => {
    e.preventDefault();
    document.body.classList.add('drag-active');
});

document.addEventListener('dragleave', (e) => {
    if (!e.relatedTarget) {
        document.body.classList.remove('drag-active');
    }
});

document.addEventListener('drop', (e) => {
    e.preventDefault();
    document.body.classList.remove('drag-active');
});

console.log('Signsley Digital Signature Verification Tool - Enhanced Version Loaded');
console.log('Version: 3.3 - Integrity fallback tuned & multi-signature sources');
console.log('Supported file types:', CONFIG.SUPPORTED_EXTENSIONS.join(', '));