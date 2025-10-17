# Signsley Deployment Checklist

## ✅ Pre-Deployment

- [ ] All files present in project directory
- [ ] `package.json` exists with all dependencies
- [ ] `netlify.toml` configured correctly
- [ ] `netlify/functions/` directory contains all three verification functions
- [ ] `.gitignore` in place (if using Git)

## ✅ Local Testing (Recommended)

```bash
# 1. Install dependencies
npm install

# 2. Start local development server
npm run dev

# 3. Open browser to http://localhost:8888

# 4. Test with sample files:
   - [ ] Upload a signed PDF (PAdES)
   - [ ] Upload a .p7m or .p7s file (CAdES)
   - [ ] Upload a signed XML (XAdES)
   
# 5. Verify results show:
   - [ ] Signature Valid/Invalid status
   - [ ] Certificate information
   - [ ] Cryptographic verification confirmation
   - [ ] Warning messages if applicable
```

## ✅ Netlify Deployment

### Option A: CLI Deployment

```bash
# 1. Install Netlify CLI (if not already installed)
npm install -g netlify-cli

# 2. Login
netlify login

# 3. Initialize (first time only)
netlify init

# 4. Deploy
netlify deploy --prod

# 5. Note your deployment URL
# Example: https://signsley-abc123.netlify.app
```

### Option B: Git Deployment

```bash
# 1. Initialize git (if not already done)
git init

# 2. Add files
git add .

# 3. Commit
git commit -m "Initial Signsley deployment"

# 4. Create GitHub repository and push
git remote add origin https://github.com/yourusername/signsley.git
git push -u origin main

# 5. In Netlify Dashboard:
   - [ ] Click "Add new site"
   - [ ] Choose "Import an existing project"
   - [ ] Connect to GitHub
   - [ ] Select your repository
   - [ ] Verify build settings (auto-detected)
   - [ ] Click "Deploy site"
```

## ✅ Post-Deployment Verification

Visit your deployed site and verify:

- [ ] Site loads correctly
- [ ] Upload interface works
- [ ] Drag and drop functions
- [ ] File selection works
- [ ] Can upload a PDF with signature
- [ ] Verification completes successfully
- [ ] Results display correctly
- [ ] All certificate details shown
- [ ] Warnings appear if applicable
- [ ] Mobile view works properly
- [ ] HTTPS is enforced

## ✅ Function Verification

Check that serverless functions are working:

1. [ ] Open browser developer tools (F12)
2. [ ] Upload a test file
3. [ ] Check Network tab for:
   - [ ] POST request to `/.netlify/functions/verify-*`
   - [ ] Status 200 response
   - [ ] JSON response with verification results
4. [ ] Check Netlify dashboard:
   - [ ] Go to Functions tab
   - [ ] Verify all 3 functions listed
   - [ ] Check function logs for any errors

## ✅ Configuration Verification

In Netlify Dashboard:

- [ ] Build settings correct (check "Site configuration")
- [ ] Functions directory: `netlify/functions`
- [ ] Publish directory: `.`
- [ ] Node version: 18.x or higher
- [ ] Environment variables (if any) are set

## 🔧 Troubleshooting

If something doesn't work:

**Functions not responding:**
```bash
# Check function logs in Netlify Dashboard
# Go to: Site > Functions > [function-name] > Logs
```

**Build fails:**
```bash
# Check build logs in Netlify Dashboard
# Go to: Site > Deploys > [failed-deploy] > Deploy log
```

**Local dev not working:**
```bash
# Clear and reinstall
rm -rf node_modules .netlify
npm install
npm run dev
```

## 📊 Success Criteria

Your deployment is successful when:

✅ Site is accessible via HTTPS
✅ File upload works
✅ All three signature types can be verified
✅ Results show cryptographic verification
✅ Certificate details are extracted
✅ No console errors
✅ Functions respond within timeout
✅ Mobile view is functional

## 🎯 Optional Enhancements

After successful deployment, consider:

- [ ] Add custom domain
- [ ] Set up monitoring/analytics
- [ ] Add rate limiting (Netlify Add-ons)
- [ ] Configure CDN settings
- [ ] Set up alerts for function failures
- [ ] Add more supported formats
- [ ] Implement file size warnings
- [ ] Add support for batch verification

## 📝 Notes

**Remember:**
- Function timeout: 10 seconds (default)
- Max payload size: 6MB
- Files are NOT stored permanently
- All processing is stateless

**Performance:**
- First function call may be slower (cold start)
- Subsequent calls are faster
- Consider background functions for larger files

---

✅ Checklist complete? Your Signsley app is ready for production!
