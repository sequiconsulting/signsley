# Signsley - Quick Start Guide

## 🚀 Deploy to Netlify in 3 Steps

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Test Locally (Optional)
```bash
npm run dev
```
Open http://localhost:8888 in your browser

### Step 3: Deploy to Netlify

**Option A: Via Netlify CLI (Recommended)**
```bash
# Install Netlify CLI globally
npm install -g netlify-cli

# Login to your Netlify account
netlify login

# Deploy
netlify deploy --prod
```

**Option B: Via Git**
1. Push this code to GitHub
2. Go to https://app.netlify.com
3. Click "Add new site" → "Import an existing project"
4. Connect to your GitHub repository
5. Netlify auto-detects configuration
6. Click "Deploy"

## ✅ What You Get

- **Full Cryptographic Verification**: Real signature validation, not just metadata
- **PAdES Support**: PDF signatures with certificate validation
- **CAdES Support**: PKCS#7/CMS signatures
- **XAdES Support**: XML digital signatures
- **Certificate Analysis**: Validity, issuer, expiry dates
- **Self-Signed Detection**: Identifies untrusted certificates

## 📋 Features Included

✓ Signature cryptographic validation
✓ Certificate parsing and validation
✓ Expiry date checking
✓ Algorithm detection (RSA-SHA256, etc.)
✓ Signer information extraction
✓ ByteRange verification (PDF)
✓ PKCS#7 structure validation
✓ XML signature validation

## 🔒 Security & Privacy

- Files processed via serverless functions
- No permanent storage
- HTTPS encryption
- Files discarded after verification
- Stateless processing

## 📁 Project Structure

```
signsley/
├── index.html                    # Frontend UI
├── app.js                       # Client-side logic
├── package.json                 # Dependencies
├── netlify.toml                 # Netlify config
├── netlify/functions/           # Serverless functions
│   ├── verify-pades.js         # PDF verification
│   ├── verify-cades.js         # CMS verification
│   └── verify-xades.js         # XML verification
└── README.md                    # Full documentation
```

## 🛠️ Development Commands

```bash
# Install dependencies
npm install

# Run locally with hot reload
npm run dev

# Deploy to production
npm run deploy

# Deploy to Netlify (manual)
netlify deploy --prod
```

## 📦 Dependencies

The app uses:
- **node-forge**: Cryptographic operations
- **@signpdf/signpdf**: PDF signature handling
- **xmldom & xpath**: XML parsing
- **pdf-parse**: PDF parsing

All installed via `npm install`

## 🌐 After Deployment

Once deployed, you'll get:
- A public URL (e.g., https://signsley-xyz.netlify.app)
- Automatic HTTPS
- Global CDN distribution
- Serverless function endpoints

## 💡 Tips

1. **File Size Limits**: Netlify Functions have a 6MB payload limit
2. **Timeout**: Functions timeout after 10 seconds (default)
3. **Testing**: Always test locally with `npm run dev` first
4. **Custom Domain**: Add your own domain in Netlify dashboard (free)

## 🐛 Troubleshooting

**Functions not working?**
- Check `netlify.toml` functions path
- Verify `node_modules` is installed
- Check function logs in Netlify dashboard

**Local dev issues?**
- Ensure Node.js 14+ is installed
- Run `npm install` again
- Clear `.netlify` folder and restart

**Deployment fails?**
- Check `package.json` syntax
- Verify all dependencies are listed
- Check Netlify build logs

## 📚 Resources

- [Full README](README.md) - Complete documentation
- [Netlify Functions Docs](https://docs.netlify.com/functions/overview/)
- [node-forge](https://github.com/digitalbazaar/forge)

## 🎉 You're Done!

Your digital signature verification app is ready to deploy. Just follow the 3 steps above and you'll have a fully functional signature verification service running on Netlify!

---

Need help? Check the full README.md for detailed information.
