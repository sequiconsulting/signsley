// Global test setup for Signsley

// Mock console methods to reduce noise during testing
global.console = {
  ...console,
  // Keep error and warn for debugging
  error: jest.fn(),
  warn: jest.fn(),
  // Mock info and log to reduce output
  info: jest.fn(),
  log: jest.fn(),
  debug: jest.fn()
};

// Mock global objects that might not be available in test environment
global.fetch = jest.fn();
global.btoa = jest.fn((str) => Buffer.from(str, 'binary').toString('base64'));
global.atob = jest.fn((str) => Buffer.from(str, 'base64').toString('binary'));

// Mock crypto for PKI.js
const crypto = require('crypto');
if (!global.crypto) {
  global.crypto = {
    webcrypto: crypto.webcrypto,
    getRandomValues: (arr) => {
      return crypto.randomFillSync(arr);
    }
  };
}

// Set up test timeout
jest.setTimeout(10000);

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global test utilities
global.testUtils = {
  // Create mock event for serverless function testing
  createMockEvent: (httpMethod = 'POST', body = null) => ({
    httpMethod,
    body: body ? JSON.stringify(body) : null,
    headers: {
      'content-type': 'application/json'
    },
    queryStringParameters: null,
    pathParameters: null
  }),
  
  // Create sample base64 PDF data
  createSamplePDF: (content = '%PDF-1.4\ntest content') => {
    return Buffer.from(content).toString('base64');
  },
  
  // Validate response structure
  validateErrorResponse: (response) => {
    expect(response).toHaveProperty('statusCode');
    expect(response).toHaveProperty('headers');
    expect(response).toHaveProperty('body');
    
    const body = JSON.parse(response.body);
    expect(body).toHaveProperty('error');
    expect(body).toHaveProperty('valid', false);
    
    return body;
  },
  
  // Validate success response
  validateSuccessResponse: (response) => {
    expect(response).toHaveProperty('statusCode', 200);
    expect(response).toHaveProperty('headers');
    expect(response).toHaveProperty('body');
    
    const body = JSON.parse(response.body);
    expect(body).toHaveProperty('valid');
    expect(body).toHaveProperty('format');
    expect(body).toHaveProperty('fileName');
    
    return body;
  }
};

// Export for use in tests
module.exports = global.testUtils;