// Enrich result with full certificate chain technical details and robust signature date estimation
const { injectChainAndSigningTime } = require('./helpers/enrich-result');
const axios = require('axios');

async function fetchCRL(url, timeout=10000){
  const res = await axios.get(url, { responseType: 'arraybuffer', timeout });
  return Buffer.from(res.data);
}

function getExt(certificate, oid){
  try{
    if (certificate.extensions) {
      const ext = certificate.extensions.find(e => e.extnID === oid || e.id === oid);
      return ext || null;
    }
  }catch{};
  return null;
}

function extractAIAandCRL(certificate){
  const info = { crl: [], ocsp: [], caIssuers: [] };
  try{
    const aia = getExt(certificate, '1.3.6.1.5.5.7.1.1'); // AuthorityInfoAccess
    if (aia && aia.accessDescriptions){
      aia.accessDescriptions.forEach(ad => {
        const method = ad.accessMethod || ad.accesstMethod || ad.method;
        const loc = ad.accessLocation || ad.location;
        const url = (loc?.uniformResourceIdentifier || loc?.value || '').toString();
        if (!url) return;
        if (method?.toString().includes('1.3.6.1.5.5.7.48.1')) info.ocsp.push(url);
        if (method?.toString().includes('1.3.6.1.5.5.7.48.2')) info.caIssuers.push(url);
      });
    }
  }catch{};
  try{
    const cdp = getExt(certificate, '2.5.29.31'); // CRL Distribution Points
    if (cdp && cdp.distributionPoints){
      cdp.distributionPoints.forEach(dp => {
        const url = (dp.distributionPoint?.fullName?.[0]?.uniformResourceIdentifier || '').toString();
        if (url) info.crl.push(url);
      });
    }
  }catch{};
  return info;
}

function extractTechDetails(cert){
  const tech = { serial:null, signatureAlgorithm:null, publicKeyAlgorithm:null, keySize:null, san:[], policies:[], aia:[], crlDP:[] };
  try{
    tech.serial = cert.serialNumber?.toString?.() || cert.serialNumber || null;
  }catch{}
  try{
    tech.signatureAlgorithm = cert.signatureAlgorithm?.algorithmId || cert.signatureOid || null;
  }catch{}
  try{
    const spki = cert.subjectPublicKeyInfo || cert.publicKey;
    if (spki){
      tech.publicKeyAlgorithm = spki.algorithm?.algorithmId || spki.algorithm || null;
      if (spki.parsedKey?.n) tech.keySize = (spki.parsedKey.n.bitLength && spki.parsedKey.n.bitLength()) || null;
      if (spki.parsedKey?.keySize) tech.keySize = spki.parsedKey.keySize;
    }
  }catch{}
  try{
    const san = getExt(cert, '2.5.29.17');
    if (san && san.altNames){
      tech.san = san.altNames.map(a => a.value || a.uri || a.dNSName || a.iPAddress).filter(Boolean);
    }
  }catch{}
  try{
    const cps = getExt(cert, '2.5.29.32');
    if (cps && cps.policies){
      tech.policies = cps.policies.map(p => p.policyIdentifier?.toString?.() || p.id).filter(Boolean);
    }
  }catch{}
  try{
    const refs = extractAIAandCRL(cert);
    tech.aia = [...refs.ocsp, ...refs.caIssuers];
    tech.crlDP = refs.crl;
  }catch{}
  return tech;
}

function estimateSigningDate(parseResult, certInfo){
  // Prefer parseResult.signingTime; else use certificate notBefore; else now
  return parseResult?.signingTime || certInfo?.validFrom || new Date();
}

function enrichChainWithTechDetails(result){
  if (!result || !Array.isArray(result._rawCertificates)) return result;
  try{
    const chainTech = result._rawCertificates.map((c, idx) => {
      const tech = extractTechDetails(c);
      return { position: idx+1, ...tech };
    });
    result.certificateChainTechnical = chainTech;
  }catch{}
  return result;
}

module.exports = {
  injectChainAndSigningTime,
  fetchCRL,
  extractAIAandCRL,
  extractTechDetails,
  estimateSigningDate,
  enrichChainWithTechDetails
};
