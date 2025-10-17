// Security tests for malformed input handling
const { handler } = require('../../netlify/functions/verify-pades');

describe('Security - Malformed Input Handling', () => {
  test('should handle null fileData safely', async () => {
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: null,
        fileName: 'test.pdf'
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(400);
    expect(result.body).toContain('No file data provided');
  });

  test('should handle extremely long filename', async () => {
    const longFilename = 'a'.repeat(1000) + '.pdf';
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==', // 'test' in base64
        fileName: longFilename
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500); // Should not crash
  });

  test('should handle malicious script in filename', async () => {
    const maliciousFilename = '<script>alert("xss")</script>.pdf';
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: maliciousFilename
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
    // Filename should be handled safely without executing script
  });

  test('should handle binary data in base64', async () => {
    const binaryData = Buffer.from([0x00, 0x01, 0xFF, 0xFE]).toString('base64');
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: binaryData,
        fileName: 'binary.pdf'
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
  });

  test('should handle unicode in filename', async () => {
    const unicodeFilename = 'Hello世界.pdf'; // Hello世界.pdf
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: unicodeFilename
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
  });

  test('should handle deeply nested JSON', async () => {
    const deepObject = { a: { b: { c: { d: { e: 'deep' } } } } };
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: 'test.pdf',
        extraData: deepObject
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
  });
});