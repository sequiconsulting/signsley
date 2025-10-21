# Signsley - Digital Signature Verification Service

**Python Backend with pyhanko 0.31** - Professional digital signature verification supporting PAdES, CAdES, and XAdES formats.

[![Netlify Status](https://api.netlify.com/api/v1/badges/your-badge-id/deploy-status)](https://app.netlify.com/sites/your-site/deploys)

## 🆕 What's New in v4.1

- **Upgraded to pyhanko 0.31**: Professional-grade PDF signature verification
- **Enhanced Security**: Advanced certificate chain validation and revocation checking
- **Better Standards Compliance**: Full AdES compliance validation
- **Python Backend**: Improved cryptographic verification capabilities
- **Netlify Functions**: Serverless Python runtime for scalable verification

## 🚀 Features

### Signature Formats Supported
- **PAdES** (PDF Advanced Electronic Signatures) - Full cryptographic verification
- **CAdES** (CMS Advanced Electronic Signatures) - Structural validation
- **XAdES** (XML Advanced Electronic Signatures) - XML signature analysis

### Verification Capabilities
- ✅ **Document Integrity**: Cryptographic hash verification
- ✅ **Certificate Validation**: Chain validation and time-based checks
- ✅ **Revocation Checking**: OCSP and CRL validation
- ✅ **Multiple Signatures**: Support for documents with multiple signatures
- ✅ **AdES Compliance**: Standards compliance validation
- ✅ **Timestamp Validation**: Trusted timestamping verification

## 🏗️ Architecture

### Frontend
- **HTML/CSS/JavaScript**: Clean, responsive user interface
- **Drag & Drop**: Easy file upload with progress indicators
- **Real-time Feedback**: Comprehensive verification results display

### Backend (NEW)
- **Python 3.11**: Modern Python runtime
- **pyhanko 0.31**: Professional PDF signature library
- **Netlify Functions**: Serverless Python execution
- **FastAPI Core**: High-performance API framework (for local development)

## 🛠️ Development Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend build tools)
- Git

### Local Development

1. **Clone and switch to branch**:
   ```bash
   git clone https://github.com/sequiconsulting/signsley.git
   cd signsley
   git checkout python-backend-pyhanko-0.31
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Test locally with FastAPI**:
   ```bash
   cd api
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

4. **Access the application**:
   - Frontend: http://localhost:8000
   - API Docs: http://localhost:8000/api/docs
   - Health Check: http://localhost:8000/api/health

### Netlify Development

1. **Install Netlify CLI**:
   ```bash
   npm install -g netlify-cli
   ```

2. **Run Netlify dev server**:
   ```bash
   netlify dev
   ```

3. **Test Python functions**:
   ```bash
   # Test health check
   curl http://localhost:8888/api/health
   
   # Test PAdES verification (requires base64 PDF)
   curl -X POST http://localhost:8888/api/verify-pades \
     -H "Content-Type: application/json" \
     -d '{"fileData":"JVBERi0xLjQ=","fileName":"test.pdf"}'
   ```

## 🚀 Deployment on Netlify

### Option 1: Netlify UI (Recommended)

1. **Connect Repository**:
   - Go to [Netlify](https://app.netlify.com/)
   - Click "New site from Git"
   - Select your forked repository
   - Choose branch: `python-backend-pyhanko-0.31`

2. **Configure Build Settings**:
   ```
   Build command: (leave empty)
   Publish directory: .
   Functions directory: netlify/functions
   ```

3. **Environment Variables** (Optional):
   ```
   PYTHON_VERSION = 3.11
   LOG_LEVEL = INFO
   ```

4. **Deploy**: Click "Deploy site"

### Option 2: Netlify CLI

```bash
# Login to Netlify
netlify login

# Deploy to draft URL
netlify deploy

# Deploy to production
netlify deploy --prod
```

## 📡 API Endpoints

### Verification Endpoints
- `POST /api/verify-pades` - Verify PDF signatures (PAdES)
- `POST /api/verify-cades` - Verify CMS signatures (CAdES)
- `POST /api/verify-xades` - Verify XML signatures (XAdES)

### Utility Endpoints
- `GET /api/health` - Service health check and capabilities
- `GET /api/verify-{format}/info` - Format-specific information

### Request Format
```json
{
  "fileData": "base64-encoded-file-content",
  "fileName": "document.pdf"
}
```

### Response Format
```json
{
  "valid": true,
  "format": "PAdES",
  "fileName": "document.pdf",
  "documentIntact": true,
  "integrityReason": "Cryptographic hash verified",
  "cryptographicVerification": true,
  "signatureValid": true,
  "certificateValid": true,
  "chainValid": true,
  "revocationChecked": true,
  "revoked": false,
  "signedBy": "John Doe",
  "organization": "Example Corp",
  "signatureDate": "2024/10/22",
  "signatureCount": 1,
  "signatures": [...],
  "warnings": [],
  "verificationTimestamp": "2024-10-22T01:30:00Z",
  "processingTime": 1250
}
```

## 🔧 Configuration

### Netlify Settings

**Build Settings** (`netlify.toml`):
- Python 3.11 runtime for functions
- 30-second timeout for signature verification
- Automatic API endpoint routing
- Security headers configuration

**Environment Variables**:
```bash
PYTHON_VERSION=3.11
ENVIRONMENT=production
LOG_LEVEL=INFO
```

### Python Dependencies

Core libraries:
- `pyhanko==0.31.0` - Professional PDF signature verification
- `cryptography>=41.0.0` - Cryptographic operations
- `lxml>=4.9.0` - XML processing for XAdES
- `requests>=2.31.0` - HTTP client for revocation checking

## 📋 Migration from v4.0

### Key Changes
- **Backend**: Node.js → Python 3.11 + pyhanko 0.31
- **Endpoints**: Same API, improved verification accuracy
- **Performance**: Better cryptographic validation
- **Standards**: Enhanced AdES compliance

### Backwards Compatibility
- ✅ Same API interface and response format
- ✅ Same frontend (no changes needed)
- ✅ Same error handling patterns
- ✅ Same file size limits and supported formats

## 🧪 Testing

### Manual Testing

1. **PDF Signatures (PAdES)**:
   - Upload a signed PDF file
   - Verify document integrity status
   - Check certificate validation results

2. **CMS Signatures (CAdES)**:
   - Upload .p7m, .p7s, or .sig files
   - Verify structural validation
   - Review certificate information

3. **XML Signatures (XAdES)**:
   - Upload signed XML files
   - Verify XML signature structure
   - Check certificate extraction

### Automated Testing

```bash
# Test Python functions locally
cd netlify/functions
python verify-pades.py
python verify-cades.py
python verify-xades.py
python health.py
```

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**:
   ```bash
   # Ensure all dependencies are installed
   pip install -r requirements.txt
   ```

2. **Function Timeout**:
   - Large files may exceed 30-second limit
   - Consider file size optimization

3. **Module Path Issues**:
   - Ensure `__init__.py` files exist in all directories
   - Check Python path configuration in functions

4. **pyhanko Installation**:
   ```bash
   # If pyhanko fails to install
   pip install --upgrade pip setuptools wheel
   pip install pyhanko==0.31.0
   ```

### Debug Mode

```bash
# Enable detailed logging
netlify dev --debug

# Check function logs
netlify functions:log
```

## 📚 Documentation

- **pyhanko Documentation**: https://pyhanko.readthedocs.io/
- **Netlify Functions**: https://docs.netlify.com/functions/overview/
- **AdES Standards**: ETSI EN 319 122/132/142

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch from `python-backend-pyhanko-0.31`
3. Make your changes
4. Test thoroughly with various signature types
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## 🔗 Links

- **Production**: https://signsley.netlify.app/
- **Repository**: https://github.com/sequiconsulting/signsley
- **Issues**: https://github.com/sequiconsulting/signsley/issues
- **Greensley**: https://www.greensley.eu

---

**Powered by pyhanko 0.31 + Python** | **© 2025 [Greensley](https://www.greensley.eu)**