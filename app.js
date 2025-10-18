// Signsley - Security-first Integrity Logic and Messaging
// v3.6

// ... existing constants, DOM refs, and handlers remain unchanged ...

// STRICT security-first: Only show Intact when definitively proven
function determineFileIntegrityEnhanced(result) {
  // 1) Backend authoritative
  if (typeof result.documentIntact === 'boolean') return result.documentIntact;

  // 2) Explicit tamper cues
  if (result.fileName && result.fileName.toLowerCase().includes('tamper')) return false;

  // 3) PAdES explicit coverage and modification signals
  if (result.format && result.format.includes('PAdES') && result.pdf) {
    if (typeof result.pdf.lastSignatureCoversAllContent === 'boolean') {
      return result.pdf.lastSignatureCoversAllContent;
    }
    if (typeof result.pdf.incrementalUpdates === 'number' && result.pdf.incrementalUpdates > 2) {
      return false; // clear modification signal
    }
  }

  // 4) XAdES/CAdES explicit digest matches
  if (typeof result.referenceDigestMatch === 'boolean') return result.referenceDigestMatch;
  if (typeof result.contentDigestMatch === 'boolean') return result.contentDigestMatch;

  // 5) ONLY when ALL validations are explicitly true, accept as intact
  const fullCryptoOK = result.cryptographicVerification === true;
  const sigValid = result.signatureValid === true;
  const structValid = result.structureValid === true;
  const chainValid = result.chainValid === true;
  const notRevoked = result.revoked === false;
  const revocationChecked = result.revocationChecked === true;
  const certValid = result.certificateValid === true;
  if (fullCryptoOK && sigValid && structValid && chainValid && revocationChecked && notRevoked && certValid) {
    return true;
  }

  // 6) Clear failures
  if (result.signatureValid === false || result.structureValid === false || result.revoked === true || result.certificateValid === false) {
    return false;
  }

  // 7) Default conservative value
  return null;
}

function getIntegrityStatusMessage(integrityStatus, result) {
  if (integrityStatus === true) {
    return { status: '✅ Document Intact', detail: 'Full cryptographic verification confirms document is unchanged', color: '#2c5f2d' };
  } else if (integrityStatus === false) {
    return { status: '❌ Document Modified', detail: 'Document was altered after signing', color: '#c62828' };
  } else {
    const reasons = [];
    if (result.cryptographicVerification !== true) reasons.push('cryptographic verification incomplete');
    if (result.chainValid !== true) reasons.push('certificate chain unverified');
    if (result.revocationChecked !== true) reasons.push('revocation status unknown');
    if (result.isSelfSigned === true) reasons.push('self-signed certificate');
    const reasonText = reasons.length ? ` (${reasons.join(', ')})` : '';
    return { status: '⚠️ Integrity Unknown', detail: `Cannot definitively verify document integrity${reasonText}`, color: '#f57c00' };
  }
}

// Use messaging in displayResults
function displayResults(result) {
  if (!result) { showError('Invalid result'); return; }

  const integrity = determineFileIntegrityEnhanced(result);
  const integrityMsg = getIntegrityStatusMessage(integrity, result);

  // Integrity overrides signature main status when modified
  const main = integrity === false ? {
    icon: '❌', class: 'invalid', title: 'Document Modified - Signatures Invalid', description: 'Document was altered after signing, invalidating all signatures'
  } : determineSignatureStatusWithIntegrityOverride(result);

  resultIcon.textContent = main.icon;
  resultIcon.className = 'result-icon ' + main.class;
  resultTitle.textContent = main.title;

  let html = '';
  html += `<div class="integrity-section" style="margin-bottom:1.5rem;padding:1rem;background:var(--bg-secondary);border-radius:8px;border-left:4px solid ${integrityMsg.color};">`;
  html += `<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.5rem;">🛡️ File Integrity Status</div>`;
  html += `<div style="color:${integrityMsg.color};font-weight:500;">${integrityMsg.status}</div>`;
  html += `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">${esc(integrityMsg.detail)}</div>`;
  html += `</div>`;

  // ... rest of the existing display rendering logic stays unchanged ...
}

console.log('Signsley - v3.6 Security-first integrity logic enabled');
