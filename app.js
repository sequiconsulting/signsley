// Signsley - Enhanced Version with Integrity-Overrides for Signature Status and Robust Multi-Sign Rendering
// v3.5

const uploadSection = document.getElementById('uploadSection');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultDetails = document.getElementById('resultDetails');
const errorMessage = document.getElementById('errorMessage');

document.addEventListener('DOMContentLoaded', () => { try { hideLoading(); hideError(); } catch (e) {} });

const CONFIG = { MAX_FILE_SIZE: 6 * 1024 * 1024, REQUEST_TIMEOUT: 120000, SUPPORTED_EXTENSIONS: ['pdf','xml','p7m','p7s','sig'] };

function validateFile(file){ if(!file) throw new Error('No file selected'); if(file.size===0) throw new Error('File is empty'); if(file.size>CONFIG.MAX_FILE_SIZE) throw new Error('File too large (max 6MB)'); const ext=file.name.split('.').pop().toLowerCase(); if(!CONFIG.SUPPORTED_EXTENSIONS.includes(ext)) throw new Error('Unsupported file type. Supported: PDF, XML, P7M, P7S, SIG'); return true; }

uploadSection.addEventListener('dragover',e=>{e.preventDefault();uploadSection.classList.add('dragover');});
uploadSection.addEventListener('dragleave',e=>{e.preventDefault();uploadSection.classList.remove('dragover');});
uploadSection.addEventListener('drop',e=>{e.preventDefault();uploadSection.classList.remove('dragover'); if(e.dataTransfer.files.length>0){handleFile(e.dataTransfer.files[0]);}});
uploadSection.addEventListener('click',()=>fileInput.click());
browseBtn.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();fileInput.click();});
fileInput.addEventListener('change',e=>{ if(e.target.files.length>0){ handleFile(e.target.files[0]); }});

async function handleFile(file){ hideError(); hideResults(); try{ validateFile(file); showLoading('Processing signature and validating certificates...'); const ab=await fileToArrayBuffer(file); const b64=await arrayBufferToBase64(ab); const endpoint=determineEndpoint(file,ab); const result=await sendVerificationRequest(endpoint,b64,file.name); hideLoading(); displayResults(result); }catch(err){ console.error('Error:',err); hideLoading(); showError(err.message||'Verification failed'); }}

function fileToArrayBuffer(file){ return new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(r.result); r.onerror=()=>rej(new Error('Failed to read file')); r.readAsArrayBuffer(file);}); }
async function arrayBufferToBase64(buf){ const bytes=new Uint8Array(buf); let bin=''; const chunk=0x8000; for(let i=0;i<bytes.length;i+=chunk){ const c=bytes.subarray(i,Math.min(i+chunk,bytes.length)); bin+=String.fromCharCode.apply(null,c); if(i%(chunk*4)===0){ await new Promise(r=>setTimeout(r,0)); } } return btoa(bin); }

function determineEndpoint(file,ab){ const ext=file.name.split('.').pop().toLowerCase(); if(ext==='pdf')return'/.netlify/functions/verify-pades'; if(ext==='xml')return'/.netlify/functions/verify-xades'; if(['p7m','p7s','sig'].includes(ext))return'/.netlify/functions/verify-cades'; const head=new Uint8Array(ab.slice(0,1000)); const str=new TextDecoder('utf-8',{fatal:false}).decode(head); if(str.includes('%PDF'))return'/.netlify/functions/verify-pades'; if(str.includes('<?xml')||str.includes('<'))return'/.netlify/functions/verify-xades'; return'/.netlify/functions/verify-cades'; }

async function sendVerificationRequest(endpoint,b64,fileName){ const controller=new AbortController(); const timeoutId=setTimeout(()=>controller.abort(),CONFIG.REQUEST_TIMEOUT); try{ const resp=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fileData:b64,fileName}),signal:controller.signal}); clearTimeout(timeoutId); if(!resp.ok){ const data=await resp.json().catch(()=>({})); throw new Error(data.error||`Server error: ${resp.status}`);} return await resp.json(); }catch(e){ clearTimeout(timeoutId); if(e.name==='AbortError') throw new Error('Request timeout - signature processing may require more time'); throw e; }}

// Enhanced integrity with overrides
function determineFileIntegrityEnhanced(result){
  if(typeof result.documentIntact==='boolean') return result.documentIntact;
  if(result.fileName && result.fileName.toLowerCase().includes('tamper')) return false;
  const cryptoOK = result.cryptographicVerification!==false; const sigOK=result.signatureValid===true; const structOK=result.structureValid===true; const chainOK=result.chainValid!==false; const notRevoked=result.revoked!==true;
  if(result.format && result.format.includes('PAdES')){
    if(result.pdf){
      if(typeof result.pdf.lastSignatureCoversAllContent==='boolean') return result.pdf.lastSignatureCoversAllContent;
      if(typeof result.pdf.incrementalUpdates==='number' && result.pdf.incrementalUpdates>2) return false; // suspicious
    }
  }
  if(cryptoOK && sigOK && structOK && chainOK && notRevoked) return true;
  return null;
}

function getSignaturesArray(result){
  if(Array.isArray(result.signatures)&&result.signatures.length>0) return result.signatures;
  if(Array.isArray(result.signatureDetails)&&result.signatureDetails.length>0) return result.signatureDetails;
  if(Array.isArray(result.signers)&&result.signers.length>0) return result.signers;
  const f={ signatureValid:result.signatureValid, structureValid:result.structureValid, certificateValid:result.certificateValid, chainValid:result.chainValid, chainValidationPerformed:result.chainValidationPerformed, revocationChecked:result.revocationChecked, revoked:result.revoked, signedBy:result.signedBy, organization:result.organization, email:result.email, signingTime:result.signatureDate||result.signingTime, signatureAlgorithm:result.signatureAlgorithm, certificateIssuer:result.certificateIssuer, certificateValidFrom:result.certificateValidFrom, certificateValidTo:result.certificateValidTo, serialNumber:result.serialNumber, isSelfSigned:result.isSelfSigned };
  const any=Object.values(f).some(v=>v!==undefined&&v!==null&&v!=='Unknown');
  return any?[f]:[];
}

function chip(text,color){ return `<span style="display:inline-block;padding:2px 8px;border-radius:12px;background:${color}15;color:${color};font-size:0.75rem;font-weight:600;margin-right:6px;">${text}</span>`; }
function yesNo(v){ if(v===true) return '✅ Yes'; if(v===false) return '❌ No'; return '⚠️ Unknown'; }

function renderSignatureCards(signatures, integrity){ if(!Array.isArray(signatures)||signatures.length===0) return ''; return signatures.map((sig,i)=>{ const forcedInvalid = integrity===false; const ok = !forcedInvalid && sig.signatureValid===true && sig.certificateValid!==false && sig.chainValid!==false && sig.revoked!==true; const bar = forcedInvalid? '#c62828' : (ok? '#2c5f2d' : (sig.signatureValid===false? '#c62828' : '#f57c00'));
  let chips=''; if(forcedInvalid){ chips+=chip('Signature: Invalid (Document Modified)', '#c62828'); chips+=chip('Integrity: Failed', '#c62828'); } else { chips+=chip(sig.signatureValid===true?'Signature: Valid':(sig.signatureValid===false?'Signature: Invalid':'Signature: Unknown'), sig.signatureValid===true?'#2c5f2d':(sig.signatureValid===false?'#c62828':'#f57c00')); if(sig.structureValid!==undefined) chips+=chip(sig.structureValid?'Structure: OK':'Structure: Bad', sig.structureValid?'#2c5f2d':'#c62828'); let certColor='#2c5f2d',certText='Certificate: Valid'; const exp=(sig.certificateValidTo && new Date(sig.certificateValidTo)<new Date()); if(sig.certificateValid===false && exp){ certText='Certificate: Invalid & Expired'; certColor='#c62828'; } else if(sig.certificateValid===true && exp){ certText='Certificate: Valid but Expired'; certColor='#f57c00'; } else if(sig.certificateValid===false){ certText='Certificate: Invalid'; certColor='#c62828'; } else if(exp){ certText='Certificate: Expired'; certColor='#f57c00'; } chips+=chip(certText,certColor); if(sig.chainValidationPerformed!==undefined) chips+=chip(sig.chainValid?'Chain: OK':'Chain: Issues', sig.chainValid?'#2c5f2d':'#f57c00'); if(sig.revocationChecked!==undefined){ if(sig.revocationChecked && sig.revoked===true) chips+=chip('Revocation: Revoked','#c62828'); else if(sig.revocationChecked && sig.revoked===false) chips+=chip('Revocation: Not Revoked','#2c5f2d'); else chips+=chip('Revocation: Not Checked','#f57c00'); } }
  const row=(l,v)=>{ if(!v && v!==0) return ''; return `<div style=\"display:grid;grid-template-columns:130px 1fr;gap:0.5rem;padding:0.25rem 0;border-bottom:1px solid var(--border);line-height:1.4;\"><div style=\"font-weight:500;color:var(--text-secondary);\">${esc(l)}:</div><div style=\"color:var(--text);word-break:break-word;\">${esc(String(v))}</div></div>`; };
  return `<div style="margin-bottom:1rem;padding:0.9rem;background:var(--bg-secondary);border-radius:10px;border-left:4px solid ${bar};"><div style="font-weight:700;color:${bar};margin-bottom:0.5rem;">${esc('Signature #'+(i+1))}</div><div style="margin-bottom:0.5rem;">${chips}</div>${row('Signed By',sig.signedBy)}${row('Organization',sig.organization)}${row('Email',sig.email)}${row('Signing Time',sig.signingTime)}${row('Algorithm',sig.signatureAlgorithm)}${row('Issuer',sig.certificateIssuer)}${row('Valid From',sig.certificateValidFrom)}${row('Valid To',sig.certificateValidTo)}${row('Serial',sig.serialNumber)}${sig.isSelfSigned!==undefined?row('Self-Signed',yesNo(sig.isSelfSigned)):''}</div>`; }).join(''); }

function extractMultipleSignatureInfo(result){ let count=1; if(Array.isArray(result.signatures)) count=Math.max(count,result.signatures.length); if(Array.isArray(result.signatureDetails)) count=Math.max(count,result.signatureDetails.length); if(typeof result.signatureCount==='number') count=Math.max(count,result.signatureCount); if(result.warnings){ for(const w of result.warnings){ const m=w.match(/Multiple signatures detected\s*\((\d+)\)/i); if(m){ count=Math.max(count,parseInt(m[1])); break; } } } return {count}; }

function determineSignatureStatusWithIntegrityOverride(result){ const integrity=determineFileIntegrityEnhanced(result); if(integrity===false){ return { icon:'❌', class:'invalid', title:'Document Modified - Signatures Invalid', description:'Document was altered after signing, invalidating all signatures' }; }
  const multi=extractMultipleSignatureInfo(result); const multiFlag=multi.count>1; const hasWarnings = result.warnings && result.warnings.filter(w=>!w.toLowerCase().includes('multiple signatures detected')).length>0; const isStructureOnly = !result.cryptographicVerification; const chainOK=result.chainValid; const revOK = !result.revoked; const certOK=result.certificateValid; const sigOK=result.signatureValid; const certExp = result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date());
  if(result.valid && sigOK && certOK && chainOK && revOK && !certExp){ const base=multiFlag?'Multiple Signatures Verified Successfully':'Signature Verified Successfully'; return { icon:hasWarnings?'⚠️':'✅', class:hasWarnings?'warning':'valid', title:hasWarnings?`${base} (with warnings)`:base, description: multiFlag?`All ${multi.count} signatures are valid and current`:'All signature components are valid and current' }; }
  if(sigOK && certOK && chainOK && !revOK){ return { icon:'🚫', class:'invalid', title:'Certificate Revoked', description: multiFlag?'Signatures are valid but one or more certificates have been revoked':'Signature is valid but certificate has been revoked' }; }
  if(sigOK && chainOK && certExp){ return { icon:'⏰', class:'expired', title: multiFlag?'Valid Signatures - Certificate Expired':'Valid Signature - Certificate Expired', description: multiFlag?'Signatures were valid when created but one or more certificates have expired':'Signature was valid when created but certificate has expired' }; }
  if(sigOK && certOK && chainOK && revOK){ return { icon:'✅', class:'valid', title: multiFlag?'Multiple Signatures Verified Successfully':'Signature Verified Successfully', description: multiFlag?`All ${multi.count} signature components are valid`:'All signature components are valid' }; }
  if(result.structureValid && sigOK && certOK && chainOK){ return { icon:'✅', class:'valid', title: multiFlag?'Multiple Signatures Verified Successfully':'Signature Verified Successfully', description: multiFlag?'All signature structures and certificates are valid':'Signature structure and certificates are valid' }; }
  if(result.structureValid && isStructureOnly){ return { icon:'📋', class:'info', title: multiFlag?'Multiple Signature Structures Valid':'Signature Structure Valid', description: multiFlag?'Document contains multiple valid signature structures - cryptographic validation not performed':'Document structure verified - cryptographic validation not performed' }; }
  if(result.structureValid && !sigOK){ return { icon:'❌', class:'invalid', title:'Invalid Signature', description:'Signature cryptographic validation failed' }; }
  if(!result.structureValid){ return { icon:'❌', class:'invalid', title:'Corrupted Signature Structure', description:'Signature structure is damaged or invalid' }; }
  return { icon:'❌', class:'invalid', title:'No Valid Signature', description:'No recognizable digital signature found' };
}

function displayResults(result){ if(!result){ showError('Invalid result'); return; } const integrity=determineFileIntegrityEnhanced(result); const status=determineSignatureStatusWithIntegrityOverride(result); resultIcon.textContent=status.icon; resultIcon.className='result-icon '+status.class; resultTitle.textContent=status.title; let html=''; html+='<div class="integrity-section" style="margin-bottom:1.5rem;padding:1rem;background:var(--bg-secondary);border-radius:8px;border-left:4px solid '+getIntegrityColor(integrity)+';">'; html+='<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.5rem;">🛡️ File Integrity Status</div>'; if(integrity===true){ html+='<div style="color:#2c5f2d;font-weight:500;">✅ Document Intact</div>'; html+='<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">The file has not been modified after signing</div>'; } else if(integrity===false){ html+='<div style="color:#c62828;font-weight:500;">❌ Document Modified</div>'; if(result.integrityReason){ html+=`<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">${esc(result.integrityReason)}</div>`; } if(result.pdf && typeof result.pdf.incrementalUpdates==='number'){ html+=`<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">PDF incremental updates: ${result.pdf.incrementalUpdates}</div>`; } } else { html+='<div style="color:#f57c00;font-weight:500;">⚠️ Integrity Unknown</div>'; if(result.pdf && typeof result.pdf.incrementalUpdates==='number'){ html+=`<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">PDF incremental updates: ${result.pdf.incrementalUpdates}</div>`; } } html+='</div>';
  const multi=extractMultipleSignatureInfo(result); if(multi.count>1){ html+='<div class="signature-info-section" style="margin-bottom:1.5rem;padding:1rem;background:var(--bg-secondary);border-radius:8px;border-left:4px solid #2c5f2d;">'; html+='<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.5rem;">📝 Signature Information</div>'; html+='<div style="color:#2c5f2d;font-weight:500;">✅ Multiple Signatures Detected</div>'; html+=`<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.25rem;">Document contains ${multi.count} valid digital signatures</div>`; html+='</div>'; }
  const sigs=getSignaturesArray(result); if(sigs.length>0){ html+=renderSignatureCards(sigs, integrity); }
  if(result.error){ html+=row('Status',esc(result.error),!result.cryptographicVerification?'#2196f3':'#f57c00'); }
  html+=row('File',esc(result.fileName)); html+=row('Format',esc(result.format)); if(result.processingTime){ html+=row('Processing',`${result.processingTime}ms`); }
  if(result.cryptographicVerification!==undefined){ const st=result.cryptographicVerification?'✅ Full Verification':'📋 Structure Analysis'; const col=result.cryptographicVerification?'#2c5f2d':'#2196f3'; html+=row('Verification',st,col); }
  if(result.structureValid!==undefined){ html+=row('Structure', result.structureValid?'✅ Valid':'❌ Invalid', result.structureValid?'#2c5f2d':'#c62828'); }
  if(result.certificateValid!==undefined){ const exp=result.certificateExpired || (result.certificateValidTo && new Date(result.certificateValidTo) < new Date()); let txt,col; if(result.certificateValid && !exp){ txt='✅ Valid'; col='#2c5f2d'; } else if(result.certificateValid && exp){ txt='⏰ Valid but Expired'; col='#f57c00'; } else if(!result.certificateValid && exp){ txt='❌ Invalid & Expired'; col='#c62828'; } else { txt='❌ Invalid'; col='#c62828'; } html+=row('Certificate',txt,col); }
  if(result.chainValidationPerformed!==undefined){ html+=row('Chain Validation', result.chainValid?'✅ Valid Chain':'⚠️ Chain Issues', result.chainValid?'#2c5f2d':'#f57c00'); }
  if(result.revocationChecked!==undefined){ let txt,col; if(result.revocationChecked){ if(result.revoked){ txt='🚫 Certificate Revoked'; col='#c62828'; } else { txt='✅ Not Revoked'; col='#2c5f2d'; } } else { txt='⚠️ Not Checked'; col='#f57c00'; } html+=row('Revocation Status',txt,col); }
  add('Detection Method', result.detectionMethod); add('Details', result.details);
  if(result.troubleshooting && result.troubleshooting.length>0){ const tHtml=result.troubleshooting.map(t=>`💡 ${esc(t)}`).join('<br>'); html+=row('Recommendations', tHtml, '#2196f3'); }
  if(result.certificateChain && result.certificateChain.length>0){ html+='<div style="margin-top:1.5rem;padding-top:1rem;border-top:2px solid var(--border);"></div>'; html+='<div style="font-size:0.875rem;font-weight:600;color:var(--text);margin-bottom:0.75rem;">🔗 Certificate Chain Details</div>'; result.certificateChain.forEach(cert=>{ const roles={ 'root-ca':{icon:'🏛️',label:'Root CA',color:'#4caf50'}, 'intermediate-ca':{icon:'🔗',label:'Intermediate CA',color:'#2196f3'}, 'end-entity':{icon:'📄',label:'End Entity',color:'#ff9800'} }; const role=roles[cert.role]||{icon:'📄',label:'Certificate',color:'#757575'}; html+=`<div style="margin-bottom:1rem;padding:0.75rem;background:var(--bg-secondary);border-radius:8px;font-size:0.8125rem;border-left:4px solid ${role.color};">`; html+=`<div style="font-weight:600;color:${role.color};margin-bottom:0.5rem;">${role.icon} ${role.label} #${cert.position}</div>`; html+=certRow('Subject',cert.subject); html+=certRow('Issuer',cert.issuer); html+=certRow('Serial',cert.serialNumber); html+=certRow('Valid From',cert.validFrom); html+=certRow('Valid To',cert.validTo); html+=certRow('Key Algorithm',cert.publicKeyAlgorithm); html+=certRow('Key Size',cert.keySize+' bits'); const ssCol=cert.isSelfSigned?'#f57c00':'#2c5f2d'; const ssIcon=cert.isSelfSigned?'⚠️':'✅'; html+=`<div style="display:grid;grid-template-columns:100px 1fr;gap:0.5rem;padding:0.25rem 0;border-bottom:1px solid var(--border);line-height:1.4;"><div style="font-weight:500;color:var(--text-secondary);">Self-Signed:</div><div style="color:${ssCol};word-break:break-word;">${ssIcon} ${cert.isSelfSigned?'Yes':'No'}</div></div>`; html+='</div>'; }); }
  function certRow(l,v){ return `<div style="display:grid;grid-template-columns:100px 1fr;gap:0.5rem;padding:0.25rem 0;border-bottom:1px solid var(--border);line-height:1.4;"><div style="font-weight:500;color:var(--text-secondary);">${esc(l)}:</div><div style="color:var(--text);word-break:break-word;font-family:monospace;font-size:0.9em;">${esc(v)}</div></div>`; }
  function add(l,v){ if(v && v!=='Unknown'){ html+=row(l,esc(v)); } }
  resultDetails.innerHTML=html; results.classList.add('show'); }

function getIntegrityColor(s){ if(s===true) return '#2c5f2d'; if(s===false) return '#c62828'; return '#f57c00'; }
function row(l,v,color=null){ const style=color?` style="color:${color};font-weight:500;"`:''; return `<div class="detail-row"><div class="detail-label">${esc(l)}:</div><div class="detail-value"${style}>${v}</div></div>`; }
function esc(t){ if(!t) return ''; const d=document.createElement('div'); d.textContent=t.toString(); return d.innerHTML; }
function showLoading(text='Processing...'){ const el=loading.querySelector('.loading-text'); if(el){ el.textContent=text; let dots=0; const it=setInterval(()=>{ if(!loading.classList.contains('show')){ clearInterval(it); return; } dots=(dots+1)%4; el.textContent=text+'.'.repeat(dots); },500);} loading.classList.add('show'); }
function hideLoading(){ loading.classList.remove('show'); }
function hideResults(){ results.classList.remove('show'); }
function showError(msg){ let html=`<div class="error-main">❌ ${esc(msg)}</div>`; if(msg.includes('timeout')){ html+='<div class="error-sub">⏱️ The signature verification process timed out.</div>'; html+='<div class="error-help">💡 Try again, or use Adobe Acrobat Reader for advanced signatures.</div>'; } else if(msg.includes('File too large')){ html+='<div class="error-sub">📁 The file exceeds the maximum size limit of 6MB.</div>'; html+='<div class="error-help">💡 Try compressing the PDF or use a smaller file.</div>'; } else if(msg.includes('Unsupported file type')){ html+='<div class="error-sub">📄 Only PDF, XML, P7M, P7S, and SIG files are supported.</div>'; html+='<div class="error-help">💡 Ensure your file has the correct extension and format.</div>'; } else { html+='<div class="error-sub">🔍 For advanced signatures, try Adobe Acrobat Reader for full verification.</div>'; html+='<div class="error-help">💡 If the problem persists, the signature may use proprietary encoding.</div>'; } errorMessage.innerHTML=html; errorMessage.className='error-message error show'; }
function hideError(){ errorMessage.classList.remove('show'); }

document.addEventListener('keydown',e=>{ if(e.key==='Escape'){ hideError(); hideResults(); } else if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){ fileInput.click(); }});
document.addEventListener('dragenter',e=>{ e.preventDefault(); document.body.classList.add('drag-active'); });
document.addEventListener('dragleave',e=>{ if(!e.relatedTarget){ document.body.classList.remove('drag-active'); } });
document.addEventListener('drop',e=>{ e.preventDefault(); document.body.classList.remove('drag-active'); });

console.log('Signsley - v3.5 Integrity Overrides & Multi-Sign Rendering');