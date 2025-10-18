// Ensure inject shim is loaded by verify-pades by requiring it here
// Netlify will treat this file as a function, but we want the shim logic to run before exports
require('./verify-pades-inject');

// Re-export the original handler from verify-pades
module.exports = require('./verify-pades');
