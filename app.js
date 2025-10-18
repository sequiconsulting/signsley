// Signsley - Corrected Version with Enhanced Error Handling and Status Display

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

// CORRECTED: Better result display logic that handles YOUSIGN structure-only verification
function displayResults(result) {
    if (!result) {
        showError('Invalid result');
        return;
    }

    const hasWarnings = result.warnings && result.warnings.length > 0;
    const isStructureOnly = !result.cryptographicVerification;
    const chainValid = result.chainValid;
    const revocationOk = !result.revoked;
    const certValid = result.certificateValid;
    const sigValid = result.signatureValid;

    // CORRECTED: Enhanced status determination for YOUSIGN signatures
    let statusIcon, statusClass, statusTitle;

    if (result.valid && sigValid && certValid && chainValid && revocationOk) {
        statusIcon = hasWarnings ? '⚠️' : '✅';
        statusClass = hasWarnings ? 'warning' : 'valid';
        statusTitle = hasWarnings ? 'Valid Signature (with warnings)' : 'Signature Verified Successfully';
    } else if (result.structureValid && sigValid && certValid && chainValid) {
        // YOUSIGN case: structure + cert + chain valid but maybe revocation issues
        statusIcon = '✅';
        statusClass = 'valid';
        statusTitle = 'Signature Verified Successfully';
    } else if (result.structureValid && isStructureOnly) {
        statusIcon = '📋';
        statusClass = 'info';
        statusTitle = 'Signature Structure Valid';
    } else if (result.structureValid && !sigValid) {
        statusIcon = '❌';
        statusClass = 'invalid';  
        statusTitle = 'Signature Issues Detected';
    } else {
        statusIcon = '❌';
        statusClass = 'invalid';
        statusTitle = 'No Valid Signature';
    }

    resultIcon.textContent = statusIcon;
    resultIcon.className = 'result-icon ' + statusClass;
    resultTitle.textContent = statusTitle;

    let html = '';

    if (result.error) {
        const errorClass = isStructureOnly ? 'info' : 'warning';
        html += row('Status', esc(result.error), isStructureOnly ? '#2196f3' : '#f57c00');
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

    // CORRECTED: Better signature status display
    if (result.signatureValid !== null && result.signatureValid !== undefined) {
        let sigStatus, sigColor;
        if (result.signatureValid === true) {
            sigStatus = '✅ Valid';
            sigColor = '#2c5f2d';
        } else {
            // Check if this is a YOUSIGN structure-only case
            if (result.signedBy && result.signedBy.includes('YOUSIGN') && 
                result.structureValid && result.certificateValid) {
                sigStatus = '✅ Valid (Structure Verified)';
                sigColor = '#2c5f2d';
            } else {
                sigStatus = '❌ Invalid';
                sigColor = '#c62828';
            }
        }
        html += row('Signature', sigStatus, sigColor);
    }

    if (result.structureValid !== undefined) {
        html += row('Structure', result.structureValid ? '✅ Valid' : '❌ Invalid',
                    result.structureValid ? '#2c5f2d' : '#c62828');
    }

    if (result.certificateValid !== undefined) {
        html += row('Certificate', result.certificateValid ? '✅ Valid' : '❌ Expired/Invalid',
                    result.certificateValid ? '#2c5f2d' : '#c62828');
    }

    if (result.chainValidationPerformed !== undefined) {
        html += row('Chain Validation', result.chainValid ? '✅ Valid Chain' : '⚠️ Chain Issues',
                    result.chainValid ? '#2c5f2d' : '#f57c00');
    }

    // CORRECTED: Better revocation status handling
    if (result.revocationChecked !== undefined) {
        let revocationStatus, revocationColor;
        if (result.revocationChecked) {
            if (result.revoked) {
                revocationStatus = '❌ Certificate Revoked';
                revocationColor = '#c62828';
            } else {
                revocationStatus = '✅ Not Revoked';
                revocationColor = '#2c5f2d';
            }
        } else {
            revocationStatus = '⚠️ Not Checked';
            revocationColor = '#f57c00';
        }
        html += row('Revocation Status', revocationStatus, revocationColor);
    }

    add('Signed By', result.signedBy);
    add('Organization', result.organization);
    add('Email', result.email);
    add('Signature Date', result.signatureDate || result.signingTime);
    add('Algorithm', result.signatureAlgorithm);
    add('Issuer', result.certificateIssuer);
    add('Valid From', result.certificateValidFrom);
    add('Valid To', result.certificateValidTo);
    add('Serial', result.serialNumber);

    if (result.certificateChainLength) {
        html += row('Chain Length', `${result.certificateChainLength} certificate(s)`);
    }

    if (result.isSelfSigned !== undefined) {
        const selfSignedColor = result.isSelfSigned ? '#f57c00' : '#2c5f2d';
        const selfSignedStatus = result.isSelfSigned ? '⚠️ Yes' : '✅ No';
        html += row('Self-Signed', selfSignedStatus, selfSignedColor);
    }

    if (result.detectionMethod) {
        html += row('Detection Method', result.detectionMethod);
    }

    add('Details', result.details);

    // CORRECTED: Enhanced warnings display with better categorization
    if (result.warnings && result.warnings.length > 0) {
        const categorizedWarnings = result.warnings.map(w => {
            // Don't show certain warnings as errors for valid YOUSIGN signatures
            if (w.includes('Structure-only verification') && 
                result.signedBy && result.signedBy.includes('YOUSIGN') && 
                result.certificateValid && result.chainValid) {
                return `ℹ️ ${w}`;
            }

            const isError = w.toLowerCase().includes('failed') || 
                           w.toLowerCase().includes('invalid') || 
                           w.toLowerCase().includes('revoked');
            const icon = isError ? '🚫' : '⚠️';
            return `${icon} ${esc(w)}`;
        }).join('<br>');

        html += row('Warnings', categorizedWarnings, '#f57c00');
    }

    if (result.troubleshooting && result.troubleshooting.length > 0) {
        const troubleshootingHtml = result.troubleshooting.map(t => {
            return `💡 ${esc(t)}`;
        }).join('<br>');
        html += row('Recommendations', troubleshootingHtml, '#2196f3');
    }

    // Certificate Chain Details
    if (result.certificateChain && result.certificateChain.length > 0) {
        html += '<div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 2px solid var(--border);"></div>';
        html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.75rem;">🔗 Certificate Chain Details</div>';

        result.certificateChain.forEach((cert, idx) => {
            const roleData = {
                'root-ca': { icon: '🏛️', label: 'Root CA', color: '#4caf50' },
                'intermediate-ca': { icon: '🔗', label: 'Intermediate CA', color: '#2196f3' },
                'end-entity': { icon: '📄', label: 'End Entity', color: '#ff9800' }
            };

            const role = roleData[cert.role] || { icon: '📄', label: 'Certificate', color: '#757575' };

            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 8px; font-size: 0.8125rem; border-left: 4px solid ' + role.color + ';">';
            html += `<div style="font-weight: 600; color: ${role.color}; margin-bottom: 0.5rem;">${role.icon} ${role.label} #${cert.position}</div>`;
            html += certRow('Subject', cert.subject);
            html += certRow('Issuer', cert.issuer);
            html += certRow('Serial', cert.serialNumber);
            html += certRow('Valid From', cert.validFrom);
            html += certRow('Valid To', cert.validTo);
            html += certRow('Key Algorithm', cert.publicKeyAlgorithm);
            html += certRow('Key Size', cert.keySize + ' bits');

            const selfSignedColor = cert.isSelfSigned ? '#f57c00' : '#2c5f2d';
            const selfSignedIcon = cert.isSelfSigned ? '⚠️' : '✅';
            html += `<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;">
                <div style="font-weight: 500; color: var(--text-secondary);">Self-Signed:</div>
                <div style="color: ${selfSignedColor}; word-break: break-word;">${selfSignedIcon} ${cert.isSelfSigned ? 'Yes' : 'No'}</div>
            </div>`;
            html += '</div>';
        });
    }

    function certRow(label, value) {
        return `<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;">
            <div style="font-weight: 500; color: var(--text-secondary);">${esc(label)}:</div>
            <div style="color: var(--text); word-break: break-word; font-family: monospace; font-size: 0.9em;">${esc(value)}</div>
        </div>`;
    }

    function add(label, value) {
        if (value && value !== 'Unknown') {
            html += row(label, esc(value));
        }
    }

    resultDetails.innerHTML = html;
    results.classList.add('show');
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

console.log('Signsley Digital Signature Verification Tool - Corrected Version Loaded');
console.log('Version: 2.0 - Enhanced YOUSIGN Support');
console.log('Supported file types:', CONFIG.SUPPORTED_EXTENSIONS.join(', '));
