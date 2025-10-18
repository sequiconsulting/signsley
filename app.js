// Signsley - Enhanced Version with Chain Validation and Revocation Checking

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
    REQUEST_TIMEOUT: 90000, // Increased for revocation checks
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

// Event listeners remain the same as before
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

function displayResults(result) {
    if (!result) {
        showError('Invalid result');
        return;
    }
    
    const hasWarnings = result.warnings && result.warnings.length > 0;
    const isStructureOnly = !result.cryptographicVerification;
    const chainValid = result.chainValid;
    const revocationOk = !result.revoked;
    
    if (result.valid && chainValid && revocationOk) {
        resultIcon.textContent = hasWarnings ? '⚠️' : '✅';
        resultIcon.className = 'result-icon ' + (hasWarnings ? 'warning' : 'valid');
        resultTitle.textContent = hasWarnings ? 'Valid Signature (with warnings)' : 'Fully Valid Signature';
    } else if (result.structureValid) {
        resultIcon.textContent = isStructureOnly ? '📋' : '⚠️';
        resultIcon.className = 'result-icon ' + (isStructureOnly ? 'info' : 'warning');
        resultTitle.textContent = isStructureOnly ? 'Signature Structure Detected' : 'Signature Issues Detected';
    } else {
        resultIcon.textContent = '❌';
        resultIcon.className = 'result-icon invalid';
        resultTitle.textContent = 'No Valid Signature';
    }
    
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

    if (result.signatureValid !== null && result.signatureValid !== undefined) {
        html += row('Signature', result.signatureValid ? '✅ Valid' : '❌ Invalid', 
                    result.signatureValid ? '#2c5f2d' : '#c62828');
    }

    if (result.structureValid !== undefined) {
        html += row('Structure', result.structureValid ? '✅ Valid' : '❌ Invalid',
                    result.structureValid ? '#2c5f2d' : '#c62828');
    }

    if (result.certificateValid !== undefined) {
        html += row('Certificate', result.certificateValid ? '✅ Valid' : '⚠️ Issues',
                    result.certificateValid ? '#2c5f2d' : '#f57c00');
    }

    // Enhanced chain validation display
    if (result.chainValidationPerformed !== undefined) {
        const chainStatus = result.chainValid ? '✅ Valid Chain' : '❌ Chain Invalid';
        const chainColor = result.chainValid ? '#2c5f2d' : '#c62828';
        html += row('Chain Validation', chainStatus, chainColor);
    }

    // Enhanced revocation status display
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

    add('Signature Type', result.signatureType);
    add('Signed By', result.signedBy);
    add('Organization', result.organization);
    add('Email', result.email);
    add('Date', result.signatureDate || result.signingTime);
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
        html += row('Self-Signed', result.isSelfSigned ? 'Yes' : 'No', selfSignedColor);
    }
    
    if (result.detectionMethod) {
        html += row('Detection Method', result.detectionMethod);
    }
    
    add('Details', result.details);
    
    if (result.warnings && result.warnings.length > 0) {
        html += row('Warnings', result.warnings.map(w => '• ' + esc(w)).join('<br>'), '#f57c00');
    }
    
    if (result.troubleshooting && result.troubleshooting.length > 0) {
        html += row('Recommendations', result.troubleshooting.map(t => '• ' + esc(t)).join('<br>'), '#2196f3');
    }
    
    // Enhanced Certificate Chain Details
    if (result.certificateChain && result.certificateChain.length > 0) {
        html += '<div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 2px solid var(--border);"></div>';
        html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.75rem;">🔗 Certificate Chain Details</div>';
        
        result.certificateChain.forEach((cert, idx) => {
            const roleIcon = cert.role === 'root-ca' ? '🏛️' : cert.role === 'intermediate-ca' ? '🔗' : '📄';
            const roleLabel = cert.role === 'root-ca' ? 'Root CA' : cert.role === 'intermediate-ca' ? 'Intermediate CA' : 'End Entity';
            
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 8px; font-size: 0.8125rem;">';
            html += `<div style="font-weight: 600; color: var(--primary); margin-bottom: 0.5rem;">${roleIcon} ${roleLabel} #${cert.position}</div>`;
            html += certRow('Subject', cert.subject);
            html += certRow('Issuer', cert.issuer);
            html += certRow('Serial', cert.serialNumber);
            html += certRow('Valid From', cert.validFrom);
            html += certRow('Valid To', cert.validTo);
            html += certRow('Key Algorithm', cert.publicKeyAlgorithm);
            html += certRow('Key Size', cert.keySize + ' bits');
            
            const selfSignedColor = cert.isSelfSigned ? '#f57c00' : '#2c5f2d';
            html += `<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;">
                <div style="font-weight: 500; color: var(--text-secondary);">Self-Signed:</div>
                <div style="color: ${selfSignedColor}; word-break: break-word;">${cert.isSelfSigned ? 'Yes' : 'No'}</div>
            </div>`;
            html += '</div>';
        });
    }
    
    function certRow(label, value) {
        return `<div style="display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;">
            <div style="font-weight: 500; color: var(--text-secondary);">${esc(label)}:</div>
            <div style="color: var(--text); word-break: break-word;">${esc(value)}</div>
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
    if (el) el.textContent = text;
    loading.classList.add('show');
}

function hideLoading() {
    loading.classList.remove('show');
}

function hideResults() {
    results.classList.remove('show');
}

function showError(message) {
    errorMessage.innerHTML = `
        <div class="error-main">${esc(message)}</div>
        <div class="error-sub">For advanced signatures, try Adobe Acrobat Reader for full verification.</div>
    `;
    errorMessage.className = 'error-message error show';
}

function hideError() {
    errorMessage.classList.remove('show');
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideError();
        hideResults();
    }
});

