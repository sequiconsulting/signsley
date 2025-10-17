// Signsley Digital Signature Verification App

const uploadSection = document.getElementById('uploadSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetails = document.getElementById('resultDetails');
const errorMessage = document.getElementById('errorMessage');

// Drag and drop handlers
uploadSection.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadSection.classList.add('dragover');
});

uploadSection.addEventListener('dragleave', () => {
    uploadSection.classList.remove('dragover');
});

uploadSection.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadSection.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFile(files[0]);
    }
});

// Click to upload
uploadSection.addEventListener('click', () => {
    fileInput.click();
});

browseBtn.addEventListener('click', (e) => {
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
    showLoading();

    try {
        const fileExtension = file.name.split('.').pop().toLowerCase();
        const arrayBuffer = await file.arrayBuffer();
        
        // Convert to base64 for transmission
        const base64Data = arrayBufferToBase64(arrayBuffer);

        let verificationResult;
        let endpoint;

        // Determine which endpoint to use
        switch (fileExtension) {
            case 'pdf':
                endpoint = '/.netlify/functions/verify-pades';
                break;
            case 'xml':
                endpoint = '/.netlify/functions/verify-xades';
                break;
            case 'p7m':
            case 'p7s':
            case 'sig':
                endpoint = '/.netlify/functions/verify-cades';
                break;
            default:
                // Try to detect format
                const uint8Array = new Uint8Array(arrayBuffer);
                const dataString = new TextDecoder().decode(uint8Array.slice(0, 1000));
                
                if (dataString.includes('%PDF')) {
                    endpoint = '/.netlify/functions/verify-pades';
                } else if (dataString.includes('<?xml') || dataString.includes('<')) {
                    endpoint = '/.netlify/functions/verify-xades';
                } else {
                    endpoint = '/.netlify/functions/verify-cades';
                }
        }

        // Call serverless function with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    fileData: base64Data,
                    fileName: file.name
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || 'Server verification failed: ' + response.statusText);
            }

            verificationResult = await response.json();
        } catch (fetchError) {
            clearTimeout(timeoutId);
            if (fetchError.name === 'AbortError') {
                throw new Error('Request timeout - file may be too large or server is busy');
            }
            throw fetchError;
        }

        hideLoading();
        displayResults(verificationResult);

    } catch (error) {
        console.error('Verification error:', error);
        hideLoading();
        showError('Error verifying signature: ' + error.message);
    }
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function displayResults(result) {
    if (result.valid) {
        resultIcon.textContent = result.warnings && result.warnings.length > 0 ? '⚠️' : '✓';
        resultIcon.className = 'result-icon ' + (result.warnings && result.warnings.length > 0 ? 'warning' : 'valid');
        resultTitle.textContent = result.warnings && result.warnings.length > 0 ? 'Signature Valid (with warnings)' : 'Signature Valid';
    } else {
        resultIcon.textContent = '✗';
        resultIcon.className = 'result-icon invalid';
        resultTitle.textContent = result.structureValid ? 'Structure Valid (Signature Not Verified)' : 'Invalid or No Signature';
    }
    
    let detailsHTML = '';
    
    if (result.error) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Error:</div>
                <div class="detail-value">${escapeHtml(result.error)}</div>
            </div>
        `;
    }
    
    detailsHTML += `
        <div class="detail-row">
            <div class="detail-label">File Name:</div>
            <div class="detail-value">${escapeHtml(result.fileName)}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Format:</div>
            <div class="detail-value">${escapeHtml(result.format)}</div>
        </div>
    `;
    
    if (result.cryptographicVerification !== undefined) {
        const verificationStatus = result.cryptographicVerification 
            ? '✓ Full Cryptographic Verification' 
            : '⚠️ Structure Validation Only';
        const statusColor = result.cryptographicVerification ? '#2c5f2d' : '#f57c00';
        
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Verification Type:</div>
                <div class="detail-value" style="color: ${statusColor}; font-weight: 500;">
                    ${verificationStatus}
                </div>
            </div>
        `;
    }

    if (result.signatureValid !== undefined && result.signatureValid !== null) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Signature Status:</div>
                <div class="detail-value" style="color: ${result.signatureValid ? '#2c5f2d' : '#c62828'}">
                    ${result.signatureValid ? '✓ Valid' : '✗ Invalid'}
                </div>
            </div>
        `;
    }

    if (result.structureValid !== undefined) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Structure Status:</div>
                <div class="detail-value" style="color: ${result.structureValid ? '#2c5f2d' : '#c62828'}">
                    ${result.structureValid ? '✓ Valid' : '✗ Invalid'}
                </div>
            </div>
        `;
    }

    if (result.certificateValid !== undefined) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Certificate Status:</div>
                <div class="detail-value" style="color: ${result.certificateValid ? '#2c5f2d' : '#c62828'}">
                    ${result.certificateValid ? '✓ Valid' : '✗ Expired/Invalid'}
                </div>
            </div>
        `;
    }

    if (result.signatureType) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Signature Type:</div>
                <div class="detail-value">${escapeHtml(result.signatureType)}</div>
            </div>
        `;
    }
    
    if (result.signedBy && result.signedBy !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Signed By:</div>
                <div class="detail-value">${escapeHtml(result.signedBy)}</div>
            </div>
        `;
    }

    if (result.organization && result.organization !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Organization:</div>
                <div class="detail-value">${escapeHtml(result.organization)}</div>
            </div>
        `;
    }

    if (result.email && result.email !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Email:</div>
                <div class="detail-value">${escapeHtml(result.email)}</div>
            </div>
        `;
    }
    
    if (result.signatureDate && result.signatureDate !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Signature Date:</div>
                <div class="detail-value">${escapeHtml(result.signatureDate)}</div>
            </div>
        `;
    }
    
    if (result.signatureAlgorithm) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Algorithm:</div>
                <div class="detail-value">${escapeHtml(result.signatureAlgorithm)}</div>
            </div>
        `;
    }
    
    if (result.certificateIssuer && result.certificateIssuer !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Certificate Issuer:</div>
                <div class="detail-value">${escapeHtml(result.certificateIssuer)}</div>
            </div>
        `;
    }

    if (result.certificateValidFrom && result.certificateValidFrom !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Certificate Valid From:</div>
                <div class="detail-value">${escapeHtml(result.certificateValidFrom)}</div>
            </div>
        `;
    }

    if (result.certificateValidTo && result.certificateValidTo !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Certificate Valid To:</div>
                <div class="detail-value">${escapeHtml(result.certificateValidTo)}</div>
            </div>
        `;
    }

    if (result.serialNumber && result.serialNumber !== 'Unknown') {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Serial Number:</div>
                <div class="detail-value">${escapeHtml(result.serialNumber)}</div>
            </div>
        `;
    }

    if (result.isSelfSigned !== undefined) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Self-Signed:</div>
                <div class="detail-value">${result.isSelfSigned ? 'Yes' : 'No'}</div>
            </div>
        `;
    }
    
    if (result.details) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Details:</div>
                <div class="detail-value">${escapeHtml(result.details)}</div>
            </div>
        `;
    }
    
    if (result.warnings && result.warnings.length > 0) {
        detailsHTML += `
            <div class="detail-row">
                <div class="detail-label">Warnings:</div>
                <div class="detail-value" style="color: #f57c00;">
                    ${result.warnings.map(w => '• ' + escapeHtml(w)).join('<br>')}
                </div>
            </div>
        `;
    }
    
    resultDetails.innerHTML = detailsHTML;
    results.classList.add('show');
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showLoading() {
    loading.classList.add('show');
}

function hideLoading() {
    loading.classList.remove('show');
}

function hideResults() {
    results.classList.remove('show');
}

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.add('show');
}

function hideError() {
    errorMessage.classList.remove('show');
}
