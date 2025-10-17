# Signsley - Digital Signature Verification

A modern web application for **full cryptographic verification** of digital signatures in various formats including PAdES, XAdES, CAdES, and ASiC. Uses Netlify Functions (serverless) for secure server-side cryptographic validation.

## Features

- **Full Cryptographic Verification**: True signature validation with certificate checking
- **Multiple Format Support**: Verifies PAdES (PDF), XAdES (XML), CAdES (PKCS#7), and other signature formats
- **Serverless Architecture**: Powered by Netlify Functions for secure server-side processing
- **Certificate Analysis**: Validates certificates, checks expiry, extracts issuer information
- **Drag & Drop Interface**: Easy-to-use interface with drag and drop support
- **Mobile Responsive**: Works seamlessly on desktop and mobile devices
- **Privacy Focused**: Files are processed but not permanently stored

## Supported Signature Formats

- **PAdES** (PDF Advanced Electronic Signatures) - `.pdf`
- **XAdES** (XML Advanced Electronic Signatures) - `.xml`
- **CAdES** (CMS Advanced Electronic Signatures) - `.p7m`, `.p7s`, `.sig`
- **ASiC** (Associated Signature Containers)

## What This App Does

✅ **Full Cryptographic Signature Verification**
✅ **Certificate Chain Validation**
✅ **Certificate Expiry Checking**
✅ **Signature Algorithm Detection**
✅ **Signer Information Extraction**
✅ **Self-Signed Certificate Detection**
✅ **ByteRange and Hash Verification (PAdES)**
✅ **PKCS#7/CMS Structure Validation (CAdES)**
✅ **XML Signature Validation (XAdES)**

⚠️ **Limitations:**
- Certificate revocation status (CRL/OCSP) requires external services
- Trust chain validation to root CAs requires additional CA bundle integration
- Timestamp validation for long-term signatures requires TSA access

## Architecture

### Frontend (Client-Side)
- HTML5, CSS3, JavaScript
- File upload and user interface
- Result display

### Backend (Netlify Functions)
- **verify-pades.js** - PAdES signature verification using node-forge
- **verify-cades.js** - CAdES/PKCS#7 verification
- **verify-xades.js** - XAdES/XML signature verification
- All functions perform cryptographic validation server-side

## Installation & Deployment

### Prerequisites
```bash
node --version  # Node.js 14+ required
npm --version   # npm 6+ required
```

### Local Development

1. Clone the repository
2. Install dependencies:
```bash
npm install
```

3. Run locally with Netlify Dev:
```bash
npm run dev
```

This will start the app at `http://localhost:8888` with serverless functions running locally.

## Deployment to Netlify

### Option 1: Deploy via Netlify CLI (Recommended)

1. Install Netlify CLI:
```bash
npm install -g netlify-cli
```

2. Login to Netlify:
```bash
netlify login
```

3. Deploy:
```bash
npm run deploy
```

### Option 2: Deploy via Git

1. Push this repository to GitHub, GitLab, or Bitbucket
2. Log in to [Netlify](https://netlify.com)
3. Click "New site from Git"
4. Select your repository
5. Build settings (auto-detected from netlify.toml):
   - Build command: `echo 'No build required'`
   - Publish directory: `.`
   - Functions directory: `netlify/functions`
6. Click "Deploy site"

### Option 3: Drag & Drop Deploy

**Note**: This method won't include the serverless functions. Use CLI or Git deployment for full functionality.

## Files Structure

```
signsley/
├── index.html                      # Main HTML file
├── app.js                         # Frontend JavaScript
├── package.json                   # Dependencies
├── netlify.toml                   # Netlify configuration
├── _redirects                     # Routing configuration
├── netlify/
│   └── functions/
│       ├── verify-pades.js       # PAdES verification function
│       ├── verify-cades.js       # CAdES verification function
│       └── verify-xades.js       # XAdES verification function
└── README.md                      # This file
```

## Technical Details

### Security Features

- Content Security Policy headers
- XSS protection
- MIME type sniffing prevention
- Clickjacking protection via X-Frame-Options
- HTTPS enforcement in production

### Dependencies

**Runtime:**
- `@signpdf/signpdf` - PDF signature handling
- `@signpdf/utils` - Signature utilities
- `node-forge` - Cryptographic operations (RSA, certificates, PKCS#7)
- `pdf-parse` - PDF parsing
- `xmldom` - XML DOM parsing
- `xpath` - XPath queries for XML

**Development:**
- `netlify-cli` - Local development and deployment

### Browser Compatibility

- Modern browsers (Chrome, Firefox, Safari, Edge)
- Requires JavaScript enabled
- File API support required

### Netlify Functions Details

- Runtime: Node.js 18.x
- Timeout: 10 seconds (synchronous)
- Memory: 1024 MB
- Region: us-east-1 (default, configurable)

## How It Works

1. **User uploads file** via drag-and-drop or file picker
2. **File is converted to Base64** in the browser
3. **Sent to appropriate Netlify Function** based on file type
4. **Server-side verification**:
   - Parse signature structure (PKCS#7, PDF, XML)
   - Extract certificate information
   - Verify cryptographic signature
   - Check certificate validity dates
   - Detect self-signed certificates
5. **Results returned** to frontend and displayed

## Privacy & Security

- Files are transmitted securely via HTTPS
- Serverless functions process files in memory only
- No files are permanently stored on any server
- Processing is stateless - each request is isolated
- Files are automatically discarded after processing

## Design Philosophy

Signsley follows a minimalist, professional design inspired by Greensley, featuring:

- Clean, uncluttered interface
- Professional color scheme (green accent: #2c5f2d)
- Clear typography and spacing
- Trustworthy and straightforward user experience

## Development

### Adding New Signature Formats

1. Create a new function in `netlify/functions/`
2. Implement verification logic
3. Update frontend `app.js` to route to new endpoint
4. Add format description to UI

### Testing

Test locally with:
```bash
netlify dev
```

Upload test files and verify output.

## Support

For issues or questions about signature standards:

- [PAdES Standard](https://www.etsi.org/deliver/etsi_ts/102700_102799/102778-01/)
- [XAdES Standard](https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/)
- [CAdES Standard](https://www.etsi.org/deliver/etsi_ts/101700_101799/101733/)
- [Netlify Functions Documentation](https://docs.netlify.com/functions/overview/)

## License

This project is provided as-is for demonstration purposes.

## Acknowledgments

- Built with [Netlify Functions](https://www.netlify.com/products/functions/)
- Uses [node-forge](https://github.com/digitalbazaar/forge) for cryptography
- Inspired by Greensley design aesthetic

---

Built with security, privacy, and modern web architecture in mind.
