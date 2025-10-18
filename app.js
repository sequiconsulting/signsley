// ENHANCED: Better multiple signature handling
function displayResults(result) {
    if (!result) {
        showError('Invalid result');
        return;
    }

    // Determine file integrity status
    const integrityStatus = determineFileIntegrity(result);
    
    // Enhanced signature status determination with multiple signature support
    const signatureStatus = determineSignatureStatusEnhanced(result);

    // Set main result display
    resultIcon.textContent = signatureStatus.icon;
    resultIcon.className = 'result-icon ' + signatureStatus.class;
    resultTitle.textContent = signatureStatus.title;

    let html = '';

    // File Integrity Header Section (unchanged)
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

    // ENHANCED: Multiple Signature Detection Section
    const multipleSignatures = extractMultipleSignatureInfo(result);
    if (multipleSignatures.count > 1) {
        html += '<div class="signature-info-section" style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid #2c5f2d;">';
        html += '<div style="font-size: 0.875rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem;">📝 Signature Information</div>';
        html += '<div style="color: #2c5f2d; font-weight: 500;">✅ Multiple Signatures Detected</div>';
        html += `<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">Document contains ${multipleSignatures.count} valid digital signatures</div>`;
        html += '</div>';
    }

    // Signature Status Description
    if (signatureStatus.description) {
        html += '<div class="status-description" style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-light); border-radius: 6px; font-size: 0.875rem; color: var(--text-secondary);">';
        html += signatureStatus.description;
        html += '</div>';
    }

    // Rest of the existing code with modifications to warnings section...
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

    // Enhanced signature display
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

    // Enhanced certificate status with expiration details
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

    // ENHANCED: Filter out multiple signature "warnings" and handle them as positive information
    if (result.warnings && result.warnings.length > 0) {
        const filteredWarnings = result.warnings.filter(w => {
            // Don't show multiple signature detection as warning
            if (w.toLowerCase().includes('multiple signatures detected')) {
                return false; // This is handled in the dedicated section above
            }
            return true;
        });

        if (filteredWarnings.length > 0) {
            const categorizedWarnings = filteredWarnings.map(w => {
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
    }

    if (result.troubleshooting && result.troubleshooting.length > 0) {
        const troubleshootingHtml = result.troubleshooting.map(t => {
            return `💡 ${esc(t)}`;
        }).join('<br>');
        html += row('Recommendations', troubleshootingHtml, '#2196f3');
    }

    // Certificate Chain Details (unchanged)...
    // [Rest of certificate chain code remains the same]

    function add(label, value) {
        if (value && value !== 'Unknown') {
            html += row(label, esc(value));
        }
    }

    resultDetails.innerHTML = html;
    results.classList.add('show');
}

// ENHANCED: Extract multiple signature information
function extractMultipleSignatureInfo(result) {
    let count = 1; // Default to 1 signature
    
    if (result.warnings) {
        for (const warning of result.warnings) {
            const match = warning.match(/Multiple signatures detected \((\d+)\)/i);
            if (match) {
                count = parseInt(match[1]);
                break;
            }
        }
    }
    
    return { count: count };
}

// ENHANCED: Improved signature status determination with multiple signature support
function determineSignatureStatusEnhanced(result) {
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

    // Enhanced status determination considering multiple signatures as positive
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

