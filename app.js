// Signsley Digital Signature Verification App - Enhanced Version

// DOM Elements
const uploadSection = document.getElementById('uploadSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetails = document.getElementById('resultDetails');
const errorMessage = document.getElementById('errorMessage');

// Configuration
const CONFIG = {
    MAX_FILE_SIZE: 6 * 1024 * 1024, // 6MB
    REQUEST_TIMEOUT: 30000, // 30 seconds
    SUPPORTED_EXTENSIONS: ['pdf', 'xml', 'p7m', 'p7s', 'sig'],
    SUPPORTED_MIME_TYPES: [
        'application/pdf',
        'application/xml', 
        'text/xml',
        'application/pkcs7-mime',
        'application/x-pkcs7-mime',
        'application/pkcs7-signature',
        'application/x-pkcs7-signature'
    ]
};

// Enhanced file validation
function validateFile(file) {
    if (!file) {
        throw new Error('No file selected');
    }
    
    // Check file size
    if (file.size === 0) {
        throw new Error('The selected file is empty. Please choose a valid file.');
    }
    
    if (file.size > CONFIG.MAX_FILE_SIZE) {
        const sizeMB = (CONFIG.MAX_FILE_SIZE / (1024 * 1024)).toFixed(1);
        throw new Error(`File is too large. Maximum size allowed is ${sizeMB}MB.`);
    }
    
    // Check file extension
    const fileName = file.name.toLowerCase();
    const extension = fileName.split('.').pop();
    
    if (!extension || !CONFIG.SUPPORTED_EXTENSIONS.includes(extension)) {
        throw new Error(`Unsupported file type. Please upload files with these extensions: ${CONFIG.SUPPORTED_EXTENSIONS.join(', ')}`);
    }
    
    // Check MIME type (if available)
    if (file.type && !CONFIG.SUPPORTED_MIME_TYPES.includes(file.type)) {
        console.warn(`Unexpected MIME type: ${file.type}`);
    }
    
    return true;
}

// Enhanced error categorization
function categorizeError(error) {
    const message = error.message || error.toString();
    
    if (message.includes('timeout') || message.includes('Request timeout')) {
        return {
            title: 'Processing Timeout',
            message: 'The file is taking too long to process. This may happen with large or complex files. Please try again or contact support if the problem persists.',
            type: 'warning'
        };
    }
    
    if (message.includes('too large') || message.includes('size')) {
        return {
            title: 'File Too Large',
            message: 'The selected file exceeds the maximum size limit of 6MB. Please choose a smaller file.',
            type: 'warning'
        };
    }
    
    if (message.includes('Unsupported file type') || message.includes('format')) {
        return {
            title: 'Unsupported Format',
            message: 'Please upload a PDF document, XML file, or digital signature file (.p7m, .p7s, .sig).',
            type: 'info'
        };
    }
    
    if (message.includes('empty') || message.includes('No file')) {
        return {
            title: 'Invalid File',
            message: 'The selected file appears to be empty or corrupted. Please choose a different file.',
            type: 'warning'
        };
    }
    
    if (message.includes('network') || message.includes('fetch')) {
        return {
            title: 'Connection Error',
            message: 'Unable to connect to the verification service. Please check your internet connection and try again.',
            type: 'error'
        };
    }
    
    if (message.includes('Server verification failed')) {
        return {
            title: 'Server Error',
            message: 'The verification service encountered an error. Please try again in a few minutes.',
            type: 'error'
        };
    }
    
    // Default error
    return {
        title: 'Verification Error',
        message: `Unable to verify the signature: ${message}`,
        type: 'error'
    };
}

// Memory cleanup helper
function cleanupMemory() {
    // Clear any large variables
    if (window.gc && typeof window.gc === 'function') {
        try {
            window.gc();
        } catch (e) {
            // Ignore GC errors
        }
    }
}

// Format date to YYYY/MM/DD
function formatDate(dateString) {
    if (!dateString || dateString === 'Unknown') return 'Unknown';
    try {
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return dateString;
        
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        
        return `${year}/${month}/${day}`;
    } catch (e) {
        return dateString;
    }
}

// Enhanced drag and drop handling
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
    
    const files = e.dataTransfer.files;
    if (files.length > 1) {
        showError('Please drop only one file at a time.');
        return;
    }
    
    if (files.length > 0) {
        handleFile(files[0]);
    }
});

uploadSection.addEventListener('click', () => {
    if (!loading.classList.contains('show')) {
        fileInput.click();
    }
});

browseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (!loading.classList.contains('show')) {
        fileInput.click();
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

// Enhanced file handling with progress tracking
async function handleFile(file) {
    hideError();
    hideResults();
    
    let arrayBuffer = null;
    let base64Data = null;
    
    try {
        // Validate file first
        validateFile(file);
        
        showLoading('Preparing file...');
        
        // Convert file to ArrayBuffer with progress
        arrayBuffer = await fileToArrayBuffer(file);
        
        showLoading('Converting file...');
        
        // Convert to base64 with chunking for large files
        base64Data = arrayBufferToBase64(arrayBuffer);
        
        showLoading('Determining file type...');
        
        // Determine endpoint based on file analysis
        const endpoint = determineEndpoint(file, arrayBuffer);
        
        showLoading('Verifying signature...');
        
        // Send request with timeout
        const result = await sendVerificationRequest(endpoint, base64Data, file.name);
        
        hideLoading();
        displayResults(result);
        
    } catch (error) {
        console.error('File processing error:', error);
        hideLoading();
        
        const categorizedError = categorizeError(error);
        showError(categorizedError.message, categorizedError.type);
        
    } finally {
        // Cleanup memory
        arrayBuffer = null;
        base64Data = null;
        cleanupMemory();
    }
}

// Convert file to ArrayBuffer with error handling
function fileToArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = () => {
            if (reader.result) {
                resolve(reader.result);
            } else {
                reject(new Error('Failed to read file'));
            }
        };
        
        reader.onerror = () => {
            reject(new Error('Error reading file: ' + (reader.error?.message || 'Unknown error')));
        };
        
        reader.onabort = () => {
            reject(new Error('File reading was aborted'));
        };
        
        try {
            reader.readAsArrayBuffer(file);
        } catch (e) {
            reject(new Error('Failed to start reading file: ' + e.message));
        }
    });
}

// Enhanced base64 conversion with chunking
function arrayBufferToBase64(buffer) {
    if (!buffer || buffer.byteLength === 0) {
        throw new Error('Invalid or empty buffer');
    }
    
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000; // 32KB chunks
    
    try {
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
            binary += String.fromCharCode.apply(null, chunk);
            
            // Allow other tasks to run
            if (i % (chunkSize * 4) === 0) {
                // Yield to browser for large files
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        
        return btoa(binary);
    } catch (e) {
        throw new Error('Failed to convert file to base64: ' + e.message);
    }
}

// Enhanced endpoint determination
function determineEndpoint(file, arrayBuffer) {
    const fileExtension = file.name.split('.').pop().toLowerCase();
    
    switch (fileExtension) {
        case 'pdf':
            return '/.netlify/functions/verify-pades';
        case 'xml':
            return '/.netlify/functions/verify-xades';
        case 'p7m':
        case 'p7s':
        case 'sig':
            return '/.netlify/functions/verify-cades';
        default:
            // Analyze file content for unknown extensions
            const uint8Array = new Uint8Array(arrayBuffer.slice(0, 1000));
            const dataString = new TextDecoder('utf-8', { fatal: false }).decode(uint8Array);
            
            if (dataString.includes('%PDF')) {
                return '/.netlify/functions/verify-pades';
            } else if (dataString.includes('<?xml') || dataString.includes('<')) {
                return '/.netlify/functions/verify-xades';
            } else {
                return '/.netlify/functions/verify-cades';
            }
    }
}

// Enhanced verification request with proper timeout handling
async function sendVerificationRequest(endpoint, base64Data, fileName) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
        controller.abort();
    }, CONFIG.REQUEST_TIMEOUT);

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                fileData: base64Data,
                fileName: fileName
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            let errorMessage = `Server error: ${response.status} ${response.statusText}`;
            
            try {
                const errorData = await response.json();
                if (errorData.error || errorData.message) {
                    errorMessage = errorData.error || errorData.message;
                }
            } catch (jsonError) {
                // Use default error message
            }
            
            throw new Error(errorMessage);
        }

        const result = await response.json();
        
        if (!result) {
            throw new Error('Invalid response from server');
        }
        
        return result;

    } catch (fetchError) {
        clearTimeout(timeoutId);
        
        if (fetchError.name === 'AbortError') {
            throw new Error('Request timeout - the file may be too large or the server is busy. Please try again.');
        }
        
        if (fetchError.message.includes('fetch')) {
            throw new Error('Network error - please check your internet connection.');
        }
        
        throw fetchError;
    }
}

// Enhanced results display with XSS prevention
function displayResults(result) {
    if (!result) {
        showError('Invalid verification result');
        return;
    }
    
    // Determine result status
    if (result.valid) {
        resultIcon.textContent = result.warnings && result.warnings.length > 0 ? '⚠️' : '✓';
        resultIcon.className = 'result-icon ' + (result.warnings && result.warnings.length > 0 ? 'warning' : 'valid');
        resultTitle.textContent = result.warnings && result.warnings.length > 0 ? 'Signature Valid (with warnings)' : 'Signature Valid';
    } else {
        resultIcon.textContent = '✗';
        resultIcon.className = 'result-icon invalid';
        resultTitle.textContent = result.structureValid ? 'Structure Valid (Signature Not Verified)' : 'Invalid or No Signature';
    }
    
    // Build details HTML with sanitization
    let detailsHTML = '';
    
    // Add error information
    if (result.error) {
        detailsHTML += createDetailRow('Error', escapeHtml(result.error));
    }
    
    // Add basic information
    detailsHTML += createDetailRow('File Name', escapeHtml(result.fileName));
    detailsHTML += createDetailRow('Format', escapeHtml(result.format));
    
    // Add verification type
    if (result.cryptographicVerification !== undefined) {
        const verificationStatus = result.cryptographicVerification 
            ? '✓ Full Cryptographic Verification' 
            : '⚠️ Structure Validation Only';
        const statusColor = result.cryptographicVerification ? '#2c5f2d' : '#f57c00';
        
        detailsHTML += createDetailRow('Verification Type', verificationStatus, statusColor);
    }

    // Add signature status
    if (result.signatureValid !== undefined && result.signatureValid !== null) {
        const statusText = result.signatureValid ? '✓ Valid' : '✗ Invalid';
        const statusColor = result.signatureValid ? '#2c5f2d' : '#c62828';
        detailsHTML += createDetailRow('Signature Status', statusText, statusColor);
    }

    // Add structure status
    if (result.structureValid !== undefined) {
        const statusText = result.structureValid ? '✓ Valid' : '✗ Invalid';
        const statusColor = result.structureValid ? '#2c5f2d' : '#c62828';
        detailsHTML += createDetailRow('Structure Status', statusText, statusColor);
    }

    // Add certificate status
    if (result.certificateValid !== undefined) {
        const statusText = result.certificateValid ? '✓ Valid' : '✗ Expired/Invalid';
        const statusColor = result.certificateValid ? '#2c5f2d' : '#c62828';
        detailsHTML += createDetailRow('Certificate Status', statusText, statusColor);
    }

    // Add signature details
    addDetailIfExists('Signature Type', result.signatureType);
    addDetailIfExists('Signed By', result.signedBy);
    addDetailIfExists('Organization', result.organization);
    addDetailIfExists('Email', result.email);
    addDetailIfExists('Signature Date', result.signatureDate || result.signingTime);
    addDetailIfExists('Algorithm', result.signatureAlgorithm);
    addDetailIfExists('Certificate Issuer', result.certificateIssuer);
    addDetailIfExists('Certificate Valid From', result.certificateValidFrom);
    addDetailIfExists('Certificate Valid To', result.certificateValidTo);
    addDetailIfExists('Serial Number', result.serialNumber);
    
    // Add chain information
    if (result.certificateChainLength !== undefined) {
        detailsHTML += createDetailRow('Certificate Chain', `${result.certificateChainLength} certificate(s)`);
    }

    if (result.isSelfSigned !== undefined) {
        detailsHTML += createDetailRow('Self-Signed', result.isSelfSigned ? 'Yes' : 'No');
    }
    
    // Add additional details
    addDetailIfExists('Details', result.details);
    
    // Add warnings
    if (result.warnings && result.warnings.length > 0) {
        const warningsText = result.warnings.map(w => '• ' + escapeHtml(w)).join('<br>');
        detailsHTML += createDetailRow('Warnings', warningsText, '#f57c00');
    }
    
    // Helper function to add detail if exists
    function addDetailIfExists(label, value) {
        if (value && value !== 'Unknown') {
            detailsHTML += createDetailRow(label, escapeHtml(value));
        }
    }
    
    resultDetails.innerHTML = detailsHTML;
    results.classList.add('show');
}

// Helper function to create detail rows
function createDetailRow(label, value, color = null) {
    const colorStyle = color ? ` style="color: ${color}; font-weight: 500;"` : '';
    return `
        <div class="detail-row">
            <div class="detail-label">${escapeHtml(label)}:</div>
            <div class="detail-value"${colorStyle}>${value}</div>
        </div>
    `;
}

// Enhanced XSS prevention
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text.toString();
    return div.innerHTML;
}

// Enhanced loading display with status
function showLoading(status = 'Processing...') {
    const loadingText = loading.querySelector('.loading-text');
    if (loadingText) {
        loadingText.textContent = status;
    }
    loading.classList.add('show');
}

function hideLoading() {
    loading.classList.remove('show');
}

function hideResults() {
    results.classList.remove('show');
}

// Enhanced error display with types
function showError(message, type = 'error') {
    errorMessage.textContent = message;
    errorMessage.className = `error-message ${type} show`;
}

function hideError() {
    errorMessage.classList.remove('show');
}

// Add keyboard accessibility
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideError();
        hideResults();
    }
});

// Add window unload cleanup
window.addEventListener('beforeunload', () => {
    cleanupMemory();
});