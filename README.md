# Signsley - Digital Signature Verification

Modern web application for cryptographic verification of digital signatures (PAdES, XAdES, CAdES) using Netlify Functions.

## Features

- ✅ **Full Cryptographic Verification** - Real signature validation
- 📄 **Multiple Formats** - PAdES (PDF), XAdES (XML), CAdES (P7M/P7S/SIG)
- 🔒 **Serverless Architecture** - Secure processing via Netlify Functions
- 📊 **Certificate Chain Analysis** - Complete chain validation
- 📅 **Signature Date Extraction** - Shows signing time
- 🎨 **Modern UI** - Professional, responsive interface

## Quick Deploy

[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/yourusername/signsley)

## Local Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Visit `http://localhost:8888`

## Deploy to Production

```bash
npm run deploy
```

## Supported Formats

- **PAdES** - PDF with embedded signatures
- **XAdES** - XML signatures
- **CAdES** - PKCS#7 signatures (.p7m, .p7s, .sig)

## Architecture

- **Frontend**: Vanilla JavaScript, modern CSS
- **Backend**: Netlify Functions (Node.js)
- **Libraries**: node-forge, xmldom, xpath

## File Size Limit

Maximum file size: 6MB

## Security

- Files are processed server-side
- No data is stored
- All processing is done in memory
- CORS enabled for API endpoints

## License

MIT License - see LICENSE.md

## Support

For issues or questions, please open an issue on GitHub.
