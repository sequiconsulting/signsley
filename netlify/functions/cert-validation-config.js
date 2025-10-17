// cert-validation-config.js - CRL/OCSP Configuration

// Known Certificate Authorities and their validation endpoints
const CA_CONFIGS = {
  // Adobe Document Cloud
  'Adobe Document Cloud': {
    crlUrls: [
      'http://crl.adobe.com/adobe-document-cloud.crl',
      'http://crl2.adobe.com/adobe-document-cloud.crl'
    ],
    ocspUrls: [
      'http://ocsp.adobe.com',
      'http://ocsp2.adobe.com'
    ],
    trustAnchor: true
  },
  
  // Aruba PEC
  'ArubaPEC S.p.A. NG CA 3': {
    crlUrls: [
      'http://crl.pec.aruba.it/ArubaPECSpaGCA3.crl',
      'http://crl2.pec.aruba.it/ArubaPECSpaGCA3.crl'
    ],
    ocspUrls: [
      'http://ocsp.pec.aruba.it',
      'http://ocsp2.pec.aruba.it'
    ],
    trustAnchor: true
  },
  
  // GlobalSign
  'GlobalSign': {
    crlUrls: [
      'http://crl.globalsign.com/gs/gsorganizationvalsha2g2.crl',
      'http://crl2.globalsign.net/gs/gsorganizationvalsha2g2.crl'
    ],
    ocspUrls: [
      'http://ocsp2.globalsign.com/gsorganizationvalsha2g2',
      'http://ocsp.globalsign.com/gsorganizationvalsha2g2'
    ],
    trustAnchor: true
  },
  
  // DigiCert
  'DigiCert': {
    crlUrls: [
      'http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl',
      'http://crl4.digicert.com/DigiCertAssuredIDRootCA.crl'
    ],
    ocspUrls: [
      'http://ocsp.digicert.com',
      'http://ocsp2.digicert.com'
    ],
    trustAnchor: true
  },
  
  // YOUSIGN (from your certificate)
  'YOUSIGN SAS - ROOT2 CA': {
    crlUrls: [
      'http://crl.yousign.com/yousign-root2-ca.crl'
    ],
    ocspUrls: [
      'http://ocsp.yousign.com'
    ],
    trustAnchor: false // Self-signed in your case
  },
  
  // Entrust
  'Entrust': {
    crlUrls: [
      'http://crl.entrust.net/2048ca.crl',
      'http://crl.entrust.net/rootca1.crl'
    ],
    ocspUrls: [
      'http://ocsp.entrust.net'
    ],
    trustAnchor: true
  },
  
  // Symantec/VeriSign
  'VeriSign': {
    crlUrls: [
      'http://crl.verisign.com/pca3-g5.crl',
      'http://SVRIntl-G3-crl.verisign.com/SVRIntlG3.crl'
    ],
    ocspUrls: [
      'http://ocsp.verisign.com',
      'http://ocsp2.verisign.com'
    ],
    trustAnchor: true
  }
};

// Configuration for validation behavior
const VALIDATION_CONFIG = {
  // Timeouts in milliseconds
  timeouts: {
    crlDownload: 15000,
    ocspRequest: 10000,
    chainValidation: 5000
  },
  
  // Cache settings
  cache: {
    crlTtl: 3600, // 1 hour
    ocspTtl: 1800, // 30 minutes
    chainTtl: 7200 // 2 hours
  },
  
  // Size limits
  limits: {
    maxCrlSize: 10 * 1024 * 1024, // 10MB
    maxChainDepth: 10,
    maxRetries: 2
  },
  
  // Validation preferences
  preferences: {
    preferOcspOverCrl: true,
    allowSelfSigned: true,
    strictChainValidation: false,
    requireTimestamp: false
  },
  
  // Known OIDs for certificate extensions
  oids: {
    crlDistributionPoints: '2.5.29.31',
    authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
    keyUsage: '2.5.29.15',
    extendedKeyUsage: '2.5.29.37',
    subjectAltName: '2.5.29.17',
    basicConstraints: '2.5.29.19',
    certificatePolicies: '2.5.29.32'
  },
  
  // OCSP request configuration
  ocsp: {
    maxAge: 24 * 60 * 60, // 24 hours
    clockSkew: 5 * 60, // 5 minutes
    nonceLength: 16
  }
};

// Fallback CRL/OCSP endpoints for unknown CAs
const FALLBACK_ENDPOINTS = {
  crlUrls: [
    // Generic CRL repositories
    'http://crl.microsoft.com/pki/mscorp/crl/msitwww2.crl',
    'http://www.microsoft.com/pki/mscorp/crl/msitwww2.crl'
  ],
  ocspUrls: [
    // Generic OCSP responders (less common)
  ]
};

// Certificate validation rules
const VALIDATION_RULES = {
  // Minimum key sizes (in bits)
  minKeySizes: {
    rsa: 2048,
    ecc: 256,
    dsa: 2048
  },
  
  // Allowed signature algorithms
  allowedSignatureAlgorithms: [
    'sha256WithRSAEncryption',
    'sha384WithRSAEncryption',
    'sha512WithRSAEncryption',
    'ecdsa-with-SHA256',
    'ecdsa-with-SHA384',
    'ecdsa-with-SHA512'
  ],
  
  // Deprecated/weak algorithms
  weakAlgorithms: [
    'sha1WithRSAEncryption',
    'md5WithRSAEncryption',
    'md2WithRSAEncryption'
  ],
  
  // Maximum certificate age (in days)
  maxCertAge: 10 * 365, // 10 years
  
  // Grace period for expired certificates (in days)
  expiredGracePeriod: 30
};

// Helper functions for configuration access
function getCaConfig(issuerCn) {
  // Try exact match first
  if (CA_CONFIGS[issuerCn]) {
    return CA_CONFIGS[issuerCn];
  }
  
  // Try partial match
  for (const [caName, config] of Object.entries(CA_CONFIGS)) {
    if (issuerCn.toLowerCase().includes(caName.toLowerCase()) ||
        caName.toLowerCase().includes(issuerCn.toLowerCase())) {
      return config;
    }
  }
  
  return null;
}

function extractUrlsFromCertificate(cert, extensionOid) {
  const urls = [];
  
  try {
    if (cert.extensions) {
      for (const ext of cert.extensions) {
        if (ext.extnID === extensionOid) {
          // This would need proper ASN.1 parsing
          // For now, return empty array
          break;
        }
      }
    }
  } catch (error) {
    console.warn(`Error extracting URLs from extension ${extensionOid}:`, error);
  }
  
  return urls;
}

function isWeakAlgorithm(algorithm) {
  return VALIDATION_RULES.weakAlgorithms.includes(algorithm);
}

function isMinimumKeySize(keyType, keySize) {
  const minSize = VALIDATION_RULES.minKeySizes[keyType.toLowerCase()];
  return minSize ? keySize >= minSize : true;
}

// Export configuration
module.exports = {
  CA_CONFIGS,
  VALIDATION_CONFIG,
  FALLBACK_ENDPOINTS,
  VALIDATION_RULES,
  getCaConfig,
  extractUrlsFromCertificate,
  isWeakAlgorithm,
  isMinimumKeySize
};
