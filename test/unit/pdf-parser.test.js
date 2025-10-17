// Unit tests for PDF parsing functions
const { extractPDFSignatureStructure, hexToBytes, determineAdvancedSignatureType } = require('../../netlify/functions/verify-pades');

describe('PDF Parser', () => {
  describe('hexToBytes', () => {
    test('should convert valid hex string to bytes', () => {
      const hex = '48656C6C6F'; // 'Hello' in hex
      const result = hexToBytes(hex);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
    });

    test('should throw error for invalid hex string', () => {
      expect(() => hexToBytes('invalid')).toThrow('Invalid hexadecimal string');
    });

    test('should handle empty hex string', () => {
      const result = hexToBytes('');
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(0);
    });
  });

  describe('determineAdvancedSignatureType', () => {
    test('should detect Adobe signatures', () => {
      const mockBytes = new Uint8Array([0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x04]);
      const result = determineAdvancedSignatureType(mockBytes);
      expect(result).toContain('Adobe');
    });

    test('should detect Aruba signatures', () => {
      const mockBytes = new Uint8Array([0x41, 0x52, 0x55, 0x42, 0x41]); // 'ARUBA'
      const result = determineAdvancedSignatureType(mockBytes);
      expect(result).toContain('Aruba');
    });

    test('should handle unknown signatures', () => {
      const mockBytes = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
      const result = determineAdvancedSignatureType(mockBytes);
      expect(result).toBe('Unknown Digital Signature');
    });
  });

  describe('extractPDFSignatureStructure', () => {
    test('should detect PDF without signature', () => {
      const pdfString = '%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>';
      const pdfBuffer = Buffer.from(pdfString);
      const result = extractPDFSignatureStructure(pdfString, pdfBuffer);
      expect(result.hasSignature).toBe(false);
    });

    test('should detect PDF with signature', () => {
      const pdfString = '%PDF-1.4\n/ByteRange [0 100 200 300]\n/Contents <48656C6C6F>';
      const pdfBuffer = Buffer.from(pdfString);
      const result = extractPDFSignatureStructure(pdfString, pdfBuffer);
      expect(result.hasSignature).toBe(true);
      expect(result.byteRange).toEqual([0, 100, 200, 300]);
    });
  });
});