// ... existing code above remains unchanged ...

function getSignaturesArray(result) {
  // Prefer a normalized array if backend provides it in the future
  if (Array.isArray(result.signatures) && result.signatures.length > 0) return result.signatures;
  if (Array.isArray(result.signatureDetails) && result.signatureDetails.length > 0) return result.signatureDetails;
  if (Array.isArray(result.signers) && result.signers.length > 0) return result.signers;
  
  // If multiple signatures detected via warning, synthesize minimal per-signature entries if available
  if (typeof result.signatureCount === 'number' && result.signatureCount > 1 && Array.isArray(result.certificateChainsBySignature)) {
    return result.certificateChainsBySignature.map((chain, idx) => ({
      index: idx,
      signatureValid: result.signatureValid,
      structureValid: result.structureValid,
      certificateValid: result.certificateValid,
      chainValid: result.chainValid,
      chainValidationPerformed: result.chainValidationPerformed,
      revocationChecked: result.revocationChecked,
      revoked: result.revoked,
      signedBy: chain && chain[0] ? (chain[0].subject || result.signedBy) : result.signedBy,
      organization: result.organization,
      email: result.email,
      signingTime: result.signatureDate || result.signingTime,
      signatureAlgorithm: result.signatureAlgorithm,
      certificateIssuer: result.certificateIssuer,
      certificateValidFrom: result.certificateValidFrom,
      certificateValidTo: result.certificateValidTo,
      serialNumber: result.serialNumber,
      isSelfSigned: result.isSelfSigned,
      certificateChain: chain
    }));
  }

  // Fallback single signature object
  const f = { 
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

    // Collapsible certificate chain panel per signature
    const chainId = `chain-panel-${i+1}`;
    let chainHtml = '';
    if (Array.isArray(sig.certificateChain) && sig.certificateChain.length > 0) {
      chainHtml += `<div class=\"chain-toggle\" data-chain-toggle=\"${chainId}\">`+
                   `<span>🔗 View certificate chain</span>`+
                   `</div>`;
      chainHtml += `<div class=\"chain-panel\" id=\"${chainId}\">`;
      sig.certificateChain.forEach(cert => {
        const roles = { 'root-ca': { icon: '🏛️', label: 'Root CA', color: '#4caf50' }, 'intermediate-ca': { icon: '🔗', label: 'Intermediate CA', color: '#2196f3' }, 'end-entity': { icon: '📄', label: 'End Entity', color: '#ff9800' } };
        const role = roles[cert.role] || { icon: '📄', label: 'Certificate', color: '#757575' };
        chainHtml += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 8px; font-size: 0.8125rem; border-left: 4px solid ' + role.color + ';">';
        chainHtml += `<div style=\"font-weight: 600; color: ${role.color}; margin-bottom: 0.5rem;\">${role.icon} ${role.label} #${cert.position}</div>`;
        chainHtml += row('Subject', cert.subject);
        chainHtml += row('Issuer', cert.issuer);
        chainHtml += row('Serial', cert.serialNumber);
        chainHtml += row('Valid From', cert.validFrom);
        chainHtml += row('Valid To', cert.validTo);
        chainHtml += row('Key Algorithm', cert.publicKeyAlgorithm);
        chainHtml += row('Key Size', cert.keySize + ' bits');
        const ssCol = cert.isSelfSigned ? '#f57c00' : '#2c5f2d';
        const ssIcon = cert.isSelfSigned ? '⚠️' : '✅';
        chainHtml += `<div style=\"display: grid; grid-template-columns: 100px 1fr; gap: 0.5rem; padding: 0.25rem 0; border-bottom: 1px solid var(--border); line-height: 1.4;\">`+
                    `<div style=\"font-weight: 500; color: var(--text-secondary);\">Self-Signed:</div>`+
                    `<div style=\"color: ${ssCol}; word-break: break-word;\">${ssIcon} ${cert.isSelfSigned ? 'Yes' : 'No'}</div>`+
                    `</div>`;
        chainHtml += '</div>';
      });
      chainHtml += `</div>`;
    }

    return `<div class=\"signature-card\" style=\"margin-bottom:1rem;padding:0.9rem;background:var(--bg-secondary);border-radius:10px;border-left:4px solid ${bar};\">`+
           `<div style=\"font-weight:700;color:${bar};margin-bottom:0.5rem;\">${esc('Signature #'+(i+1))}</div>`+
           `<div style=\"margin-bottom:0.5rem;\">${chips}</div>`+
           `${row('Signed By',sig.signedBy)}${row('Organization',sig.organization)}${row('Email',sig.email)}${row('Signing Time',sig.signingTime)}${row('Algorithm',sig.signatureAlgorithm)}${row('Issuer',sig.certificateIssuer)}${row('Valid From',sig.certificateValidFrom)}${row('Valid To',sig.certificateValidTo)}${row('Serial',sig.serialNumber)}${sig.isSelfSigned!==undefined?row('Self-Signed', yesNo(sig.isSelfSigned)):''}`+
           `${chainHtml}`+
           `</div>`;
  }).join('');
}

// ... rest of file unchanged ...
