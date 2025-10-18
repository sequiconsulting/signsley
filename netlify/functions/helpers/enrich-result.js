// Consolidated helper: export both injectChainAndSigningTime and technical extractors/estimators
const helpers = require('./cert-tech');

module.exports.injectChainAndSigningTime = function(result, parseResult){
  try {
    // Build human-readable chain
    const chain = [];
    if (parseResult && Array.isArray(parseResult.certificates)) {
      parseResult.certificates.forEach((c, idx) => {
        let cn = 'Unknown'; let issuer = 'Unknown';
        if (c.subject && c.subject.typesAndValues) {
          const cnAttr = c.subject.typesAndValues.find(a => a.type === '2.5.4.3');
          cn = cnAttr ? (cnAttr.value?.valueBlock?.value || 'Unknown') : cn;
          const issAttr = c.issuer?.typesAndValues?.find(a => a.type === '2.5.4.3');
          issuer = issAttr ? (issAttr.value?.valueBlock?.value || 'Unknown') : issuer;
        } else if (c.subject && c.subject.attributes) {
          const cnAttr = c.subject.attributes.find(a => (a.type||a.name) === '2.5.4.3' || (a.type||a.name) === 'commonName');
          cn = cnAttr ? cnAttr.value : cn;
          const issAttr = c.issuer?.attributes?.find(a => (a.type||a.name) === '2.5.4.3' || (a.type||a.name) === 'commonName');
          issuer = issAttr ? issAttr.value : issuer;
        }
        chain.push({ position: idx+1, subjectCN: cn, issuerCN: issuer });
      });
    }
    if (chain.length) result.certificateChain = chain;

    // Technical details
    try {
      if (Array.isArray(parseResult?.certificates)) {
        result._rawCertificates = parseResult.certificates;
        helpers.enrichChainWithTechDetails(result);
      }
    }catch{}

    // Signature date estimate if needed
    if (!result.signatureDate) {
      const guess = helpers.estimateSigningDate(parseResult, {});
      if (guess) result.signatureDate = guess;
    }

  } catch (e) {
    if (!result.warnings) result.warnings = [];
    result.warnings.push('Certificate chain/signing time enrichment failed');
  }
  return result;
};