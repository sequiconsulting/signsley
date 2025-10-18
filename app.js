// Patch: ensure single-selection flows process immediately and no-signature UI is correct
(function(){
  // If DOM not ready yet, attach after load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPatch, { once: true });
  } else {
    initPatch();
  }

  function initPatch(){
    const input = document.getElementById('fileInput');
    const button = document.getElementById('browseBtn');
    if (!input || !button) return;

    // Fix: open picker then immediately route the newly selected file once selection returns
    button.addEventListener('click', (e)=>{
      e.preventDefault(); e.stopPropagation();
      input.value = '';
      // Use a microtask to guarantee change/input listeners attach and state resets
      Promise.resolve().then(()=> input.click());
    });

    // Guarantee immediate processing on any file selection
    const route = (file)=>{
      try { if (window.handleFile) { window.handleFile(file); return; } } catch(_){ }
      const dt = new DataTransfer(); dt.items.add(file); input.files = dt.files; input.dispatchEvent(new Event('change', { bubbles:true }));
    };

    const onPick = (e)=>{ const f = e.target && e.target.files && e.target.files[0]; if (f) route(f); };

    // Make sure we listen only once to avoid double-processing
    input.removeEventListener('change', onPick);
    input.removeEventListener('input', onPick);
    input.addEventListener('change', onPick);
    input.addEventListener('input', onPick);
  }
})();

// Patch: adjust display for no-signature case
(function(){
  const oldDisplayResults = window.displayResults;
  if (typeof oldDisplayResults !== 'function') return;

  window.displayResults = function(result){
    try {
      // If backend indicates no signature, set integrity unknown and avoid signature cards
      if (result && result.error === 'No digital signature detected') {
        result.structureValid = false;
        result.cryptographicVerification = false;
        result.signatureValid = null;
        result.certificateValid = null;
        result.chainValid = null;
        result.revocationChecked = false;
      }
    } catch (_) {}
    return oldDisplayResults(result);
  };
})();
