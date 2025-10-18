// verify-pades integration: add technical details and expose chain and estimated signing date in response
const { injectChainAndSigningTime } = require('./helpers/enrich-result');
const { extractTechDetails, estimateSigningDate, enrichChainWithTechDetails } = require('./helpers/cert-tech');

// Patch buildUltraComprehensiveResult by wrapping after the original export if available
(function(){
  const mod = module;
  const origBuild = (typeof buildUltraComprehensiveResult === 'function') ? buildUltraComprehensiveResult : null;
  if (!origBuild) return;
  buildUltraComprehensiveResult = function(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime){
    const base = origBuild(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime);
    try{
      // Attach raw certificates for downstream enrichment
      if (parseResult && Array.isArray(parseResult.certificates)) {
        base._rawCertificates = parseResult.certificates;
      }
      // Estimated signature date if missing
      if (!base.signatureDate) {
        base.signatureDate = estimateSigningDate(parseResult, certInfo);
      }
      // Add technical details per chain cert
      enrichChainWithTechDetails(base);
      // Recompute certificateChainLength from raw
      if (Array.isArray(parseResult?.certificates)) base.certificateChainLength = parseResult.certificates.length;
      // Ensure top-level enrichment for chain display and sig date
      injectChainAndSigningTime(base, parseResult);
      return base;
    }catch(e){ return base; }
  };
})();
