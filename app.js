// Signsley - Enhanced Version with File Integrity and Improved Status Display

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

// ENHANCED: Determine file integrity status
function determineFileIntegrity(result) {
    // Check if document has been modified after signing
    if (result.documentIntact !== undefined) {
        return result.documentIntact;
    }
    
    // Fallback logic based on signature validation
    if (result.signatureValid === true && result.structureValid === true) {
        return true; // Likely intact if signature and structure are valid
    }
    
    // Check for modification indicators in warnings
    if (result.warnings) {
        const modificationWarnings = result.warnings.some(w => 
            w.toLowerCase().includes('modified') || 
            w.toLowerCase().includes('altered') ||
            w.toLowerCase().includes('tampered') ||
            w.toLowerCase().includes('hash mismatch')
        );
        if (modificationWarnings) return false;
    }
    
    // If we can't determine, return null (unknown)
    return null;
}

// ENHANCED: Determine detailed signature status
function determineSignatureStatus(result) {
    const hasWarnings = result.warnings && result.warnings.length > 0;
    const isStructureOnly = !result.cryptographicVerification;
    const chainValid = result.chainValid;
    const revocationOk = !result.revoked;
    const certValid = result.certificateValid;
    const sigValid = result.signatureValid;
    const certExpired = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());

    // Comprehensive status determination
    if (result.valid && sigValid && certValid && chainValid && revocationOk && !certExpired) {
        return {
            icon: hasWarnings ? '⚠️' : '✅',
            class: hasWarnings ? 'warning' : 'valid',
            title: hasWarnings ? 'Valid Signature (with warnings)' : 'Signature Verified Successfully',
            description: 'All signature components are valid and current'
        };
    } else if (sigValid && certValid && chainValid && !revocationOk) {
        return {
            icon: '🚫',
            class: 'invalid',
            title: 'Certificate Revoked',
            description: 'Signature is valid but certificate has been revoked'
        };
    } else if (sigValid && chainValid && certExpired) {
        return {
            icon: '⏰',
            class: 'expired',
            title: 'Valid Signature - Certificate Expired',
            description: 'Signature was valid when created but certificate has expired'
        };
    } else if (sigValid && certValid && chainValid && revocationOk) {
        return {
            icon: '✅',
            class: 'valid',
            title: 'Signature Verified Successfully',
            description: 'All signature components are valid'
        };
    } else if (result.structureValid && sigValid && certValid && chainValid) {
        return {
            icon: '✅',
            class: 'valid',
            title: 'Signature Verified Successfully',
            description: 'Signature structure and certificates are valid'
        };
    } else if (result.structureValid && isStructureOnly) {
        return {
            icon: '📋',
            class: 'info',
            title: 'Signature Structure Valid',
            description: 'Document structure verified - cryptographic validation not performed'
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

// ENHANCED: Result display with file integrity and improved status
function displayResults(result) {
    if (!result) {
        showError('Invalid result');
        return;
    }

    // Determine file integrity status
    const integrityStatus = determineFileIntegrity(result);
    
    // Determine signature status
    const signatureStatus = determineSignatureStatus(result);

    // Set main result display
    resultIcon.textContent = signatureStatus.icon;
    resultIcon.className = 'result-icon ' + signatureStatus.class;
    resultTitle.textContent = signatureStatus.title;

    let html = '';

    // ENHANCED: File Integrity Header Section
    html += '<div class="integrity-section" style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid ' + getIntegrityColor(integrityStatus) + ';">';
    html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem;">🛡️ File Integrity Status</div>';
    
    if (integrityStatus === true) {
        html += '<div style="color: #2c5f2d; font-weight: 500;">✅ Document Intact</div>';
        html += '<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">The file has not been modified after signing</div>';
    } else if (integrityStatus === false) {
        html += '<div style="color: #c62828; font-weight: 500;">❌ Document Modified</div>';
        html += '<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">The file appears to have been altered after signing</div>';
    } else {
        html += '<div style="color: #f57c00; font-weight: 500;">⚠️ Integrity Unknown</div>';
        html += '<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Unable to determine if file was modified after signing</div>';
    }
    html += '</div>';

    // Signature Status Description
    if (signatureStatus.description) {
        html += '<div class="status-description" style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-light); border-radius: 6px; font-size: 0.875rem; color: var(--text-secondary);">';
        html += signatureStatus.description;
        html += '</div>';
    }

    if (result.error) {
        const errorClass = !result.cryptographicVerification ? 'info' : 'warning';
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

    // ENHANCED: More detailed signature status display
    if (result.signatureValid !== null && result.signatureValid !== undefined) {
        let sigStatus, sigColor;
        const certExpired = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
        
        if (result.signatureValid === true) {
            if (certExpired) {
                sigStatus = '⏰ Valid (Certificate Expired)';
                sigColor = '#f57c00';
            } else {
                sigStatus = '✅ Valid';
                sigColor = '#2c5f2d';
            }
        } else {
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

    // ENHANCED: Certificate status with expiration details
    if (result.certificateValid !== undefined) {
        const certExpired = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
        let certStatus, certColor;
        
        if (result.certificateValid && !certExpired) {
            certStatus = '✅ Valid';
            certColor = '#2c5f2d';
        } else if (result.certificateValid && certExpired) {
            certStatus = '⏰ Valid but Expired';
            certColor = '#f57c00';
        } else if (!result.certificateValid && certExpired) {
            certStatus = '❌ Invalid & Expired';
            certColor = '#c62828';
        } else {
            certStatus = '❌ Invalid';
            certColor = '#c62828';
        }
        
        html += row('Certificate', certStatus, certColor);
    }

    if (result.chainValidationPerformed !== undefined) {
        html += row('Chain Validation', result.chainValid ? '✅ Valid Chain' : '⚠️ Chain Issues',
                    result.chainValid ? '#2c5f2d' : '#f57c00');
    }

    // ENHANCED: Revocation status with more detail
    if (result.revocationChecked !== undefined) {
        let revocationStatus, revocationColor;
        if (result.revocationChecked) {
            if (result.revoked) {
                revocationStatus = '🚫 Certificate Revoked';
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

    // ENHANCED: Categorized warnings with better visual hierarchy
    if (result.warnings && result.warnings.length > 0) {
        const categorizedWarnings = result.warnings.map(w => {
            // Categorize warnings by severity
            if (w.toLowerCase().includes('revoked') || w.toLowerCase().includes('invalid')) {
                return `🚫 ${esc(w)}`;
            } else if (w.toLowerCase().includes('expired')) {
                return `⏰ ${esc(w)}`;
            } else if (w.toLowerCase().includes('modified') || w.toLowerCase().includes('altered')) {
                return `🔴 ${esc(w)}`;
            } else if (w.includes('Structure-only verification') && 
                       result.signedBy && result.signedBy.includes('YOUSIGN') && 
                       result.certificateValid && result.chainValid) {
                return `ℹ️ ${esc(w)}`;
            } else {
                const isError = w.toLowerCase().includes('failed');
                const icon = isError ? '🚫' : '⚠️';
                return `${icon} ${esc(w)}`;
            }
        }).join('<br>');

        html += row('Warnings', categorizedWarnings, '#f57c00');
    }

    if (result.troubleshooting && result.troubleshooting.length > 0) {
        const troubleshootingHtml = result.troubleshooting.map(t => {
            return `💡 ${esc(t)}`;
        }).join('<br>');
        html += row('Recommendations', troubleshootingHtml, '#2196f3');
    }

    // Certificate Chain Details (unchanged)
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

// ENHANCED: Helper function for integrity color coding
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
console.log('Version: 3.0 - Enhanced File Integrity & Signature Status');
console.log('Supported file types:', CONFIG.SUPPORTED_EXTENSIONS.join(', '));

