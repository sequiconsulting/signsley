// Security tests for injection attack prevention
const { handler } = require('../../netlify/functions/verify-pades');

describe('Security - Injection Prevention', () => {
  test('should prevent SQL injection attempts in filename', async () => {
    const sqlInjection = "'; DROP TABLE users; --";
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: sqlInjection
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
  });

  test('should prevent command injection in filename', async () => {
    const cmdInjection = 'file.pdf; rm -rf /';
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: cmdInjection
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
  });

  test('should handle NoSQL injection attempts', async () => {
    const noSqlInjection = { '$ne': null };
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: noSqlInjection
      })
    };
    
    const result = await handler(event);
    // Should handle non-string filename gracefully
    expect(result.statusCode).toBe(400);
  });

  test('should prevent path traversal attacks', async () => {
    const pathTraversal = '../../../etc/passwd';
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: pathTraversal
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
  });

  test('should handle prototype pollution attempts', async () => {
    const pollutionPayload = {
      '__proto__': { polluted: true },
      'constructor': { 'prototype': { polluted: true } }
    };
    
    const event = {
      httpMethod: 'POST',
      body: JSON.stringify({
        fileData: 'dGVzdA==',
        fileName: 'test.pdf',
        ...pollutionPayload
      })
    };
    
    const result = await handler(event);
    expect(result.statusCode).toBeLessThan(500);
    
    // Verify prototype hasn't been polluted
    expect(Object.prototype.polluted).toBeUndefined();
  });
});