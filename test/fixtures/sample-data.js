// Sample test data for verification tests

module.exports = {
  // Valid PDF header
  validPDFHeader: '%PDF-1.4',
  
  // Sample PDF with signature structure
  pdfWithSignature: `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Count 1
/Kids [3 0 R]
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj

4 0 obj
<<
/Type /Sig
/Filter /Adobe.PPKLite
/SubFilter /adbe.pkcs7.detached
/ByteRange [0 100 200 300]
/Contents <48656C6C6F576F726C64>
>>
endobj

xref
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
%%EOF`,

  // Sample base64 encoded data
  sampleBase64: 'VGhpcyBpcyBhIHRlc3QgZmlsZSBjb250ZW50',
  
  // Invalid base64 data
  invalidBase64: 'This is not base64!@#$',
  
  // Common signature hex patterns
  signaturePatterns: {
    adobe: '060A2B0601040182370A0304',
    aruba: '4152554241', // 'ARUBA' in hex
    dike: '44494B45',   // 'DIKE' in hex
    infocert: '494E464F43455254' // 'INFOCERT' in hex
  },
  
  // Test certificate data (mock)
  mockCertificate: {
    subject: {
      commonName: 'Test User',
      organization: 'Test Organization',
      country: 'US',
      email: 'test@example.com'
    },
    issuer: {
      commonName: 'Test CA',
      organization: 'Test CA Organization'
    },
    validity: {
      notBefore: new Date('2023-01-01'),
      notAfter: new Date('2024-12-31')
    },
    serialNumber: '123456789'
  },
  
  // Error test cases
  errorTestCases: {
    emptyFile: '',
    nonPDFFile: 'This is not a PDF file',
    corruptedPDF: '%PDF-1.4\ncorrupted content\x00\x01\x02',
    oversizedContent: 'A'.repeat(10 * 1024 * 1024) // 10MB
  },
  
  // Security test payloads
  securityPayloads: {
    xssAttempt: '<script>alert("xss")</script>',
    sqlInjection: "'; DROP TABLE users; --",
    cmdInjection: '; rm -rf /',
    pathTraversal: '../../../etc/passwd',
    nullByte: 'test\x00.pdf',
    longString: 'A'.repeat(1000),
    unicodeString: 'Hello世界' // Hello世界
  }
};