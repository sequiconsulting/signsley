// Integration shim formerly named verify-pades.inject.js
// Renamed to verify-pades-inject.js to comply with Netlify naming (alphanumeric, hyphen, underscore)
const { injectChainAndSigningTime } = require('./helpers/enrich-result');
const { extractTechDetails, estimateSigningDate, enrichChainWithTechDetails } = require('./helpers/cert-tech');

(function(){
  const origBuild = (typeof buildUltraComprehensiveResult === 'function') ? buildUltraComprehensiveResult : null;
  if (!origBuild) return;
  buildUltraComprehensiveResult = function(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime){
    const base = origBuild(signatureInfo, parseResult, certInfo, validationResults, fileName, parsingLog, detailedLog, startTime);
    try{
      if (parseResult && Array.isArray(parseResult.certificates)) {
        base._rawCertificates = parseResult.certificates;
      }
      if (!base.signatureDate) {
        base.signatureDate = estimateSigningDate(parseResult, certInfo);
      }
      enrichChainWithTechDetails(base);
      if (Array.isArray(parseResult?.certificates)) base.certificateChainLength = parseResult.certificates.length;
      injectChainAndSigningTime(base, parseResult);
      return base;
    }catch(e){ return base; }
  };
})();
