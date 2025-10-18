// Append certificate chain expansion and signing time guessing
module.exports.injectChainAndSigningTime = function(result, parseResult){
  try {
    // Build certificate chain display from parseResult.certificates if available
    const chain = [];
    if (parseResult && Array.isArray(parseResult.certificates)) {
      parseResult.certificates.forEach((c, idx) => {
        let cn = 'Unknown'; let issuer = 'Unknown';
        // PKI.js certificate
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
    if (chain.length) {
      result.certificateChain = chain; // array for frontend to render compactly
    }

    // Guess signing time if missing: prefer parseResult.signingTime, else use certificate Not Before, else PDF metadata not available here
    if (!result.signatureDate) {
      const candidate = parseResult?.signingTime || null;
      if (candidate) {
        result.signatureDate = candidate;
      } else if (result.certificateValidFrom && result.certificateValidFrom !== 'Unknown') {
        result.signatureDate = result.certificateValidFrom;
        if (!result.warnings) result.warnings = [];
        result.warnings.push('Signing time estimated from certificate validity start');
      }
    }
  } catch (e) {
    if (!result.warnings) result.warnings = [];
    result.warnings.push('Certificate chain/signing time enrichment failed');
  }
  return result;
};
