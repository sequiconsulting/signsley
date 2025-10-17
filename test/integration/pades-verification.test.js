// Integration tests for PAdES verification
const { handler } = require('../../netlify/functions/verify-pades');

describe('PAdES Verification Integration', () => {
  const validPDFBase64 = Buffer.from('%PDF-1.4\ntest content').toString('base64');
  
  test('should handle OPTIONS request', async () => {
    const event = {
      httpMethod: 'OPTIONS',
      body: null
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(200);
    expect(result.headers['Access-Control-Allow-Origin']).toBe('*');
  });

  test('should reject non-POST requests', async () => {
    const event = {
      httpMethod: 'GET',
      body: null
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(405);
    
    const response = JSON.parse(result.body);
    expect(response.error).toContain('Method not allowed');
  });

  test('should reject requests without body', async () => {
    const event = {
      httpMethod: 'POST',
      body: null
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(400);
    
    const response = JSON.parse(result.body);
    expect(response.error).toBe('Request body is required');
  });

  test('should reject invalid JSON', async () => {
    const event = {
      httpMethod: 'POST',
      body: 'invalid json'
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(400);
    
    const response = JSON.parse(result.body);
    expect(response.error).toBe('Invalid JSON in request body');
  });

  test('should reject request without fileData', async () => {
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({ fileName: 'test.pdf' })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(400);
    
    const response = JSON.parse(result.body);
    expect(response.error).toBe('No file data provided');
  });

  test('should reject invalid base64 data', async () => {
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'invalid-base64!@#',
        fileName: 'test.pdf'
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(400);
    
    const response = JSON.parse(result.body);
    expect(response.error).toBe('Invalid Base64 data format');
  });

  test('should reject oversized files', async () => {
    const largeBase64 = 'A'.repeat(8 * 1024 * 1024); // 8MB of 'A's
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: largeBase64,
        fileName: 'large.pdf'
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(413);
    
    const response = JSON.parse(result.body);
    expect(response.error).toBe('File too large');
  });

  test('should process valid PDF without signature', async () => {
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: validPDFBase64,
        fileName: 'test.pdf'
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBe(200);
    
    const response = JSON.parse(result.body);
    expect(response.valid).toBe(false);
    expect(response.format).toBe('PAdES');
    expect(response.fileName).toBe('test.pdf');
    expect(response.error).toContain('No digital signature found');
  });
});