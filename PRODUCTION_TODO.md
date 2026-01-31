# Production Deployment TODO List

**CRITICAL: These items MUST be completed before production deployment**

---

## 🔴 CRITICAL - Security Issues

### 1. Enable reCAPTCHA Enforcement (PATCH 53)

**Status:** ⚠️ TEMPORARILY DISABLED FOR DEVELOPMENT

**Current State:**
- reCAPTCHA validation is currently **optional** in development
- Login endpoint accepts requests without reCAPTCHA token
- Middleware skips verification when no token provided

**Files to Fix:**

1. **`/Backend/validators/auth.validator.js` (Line 212-217)**
   ```javascript
   // CURRENT (Development):
   recaptchaToken: Joi.string()
     .optional()
     .allow('', null)

   // CHANGE TO (Production):
   recaptchaToken: Joi.string()
     .required()
     .messages({
       'any.required': 'reCAPTCHA token is required',
       'string.empty': 'reCAPTCHA token is required'
     })
   ```

2. **`/Backend/services/recaptcha.service.js` (Line 137-143)**
   ```javascript
   // CURRENT (Development):
   if (!token) {
     console.warn('Development mode: No token provided, skipping verification');
     return next();
   }

   // CHANGE TO (Production):
   if (!token) {
     return res.status(400).json({
       success: false,
       message: 'reCAPTCHA token is required',
       error: 'MISSING_RECAPTCHA_TOKEN',
     });
   }
   ```

**Action Required:**
1. Set up Google Cloud reCAPTCHA Enterprise
2. Configure `GOOGLE_APPLICATION_CREDENTIALS` environment variable
3. Implement frontend reCAPTCHA integration (see below)
4. Update validator to make token required
5. Remove development bypass from middleware
6. Test with valid/invalid tokens

**Risk if not fixed:** 
- ❌ Brute force attacks possible
- ❌ Automated credential stuffing
- ❌ Bot attacks on login endpoint
- ❌ CWE-306: Missing Authentication for Critical Function

---

## 🟡 HIGH PRIORITY - Infrastructure

### 2. HTTPS/TLS Configuration (PATCH 44 & 51)

**Status:** ⚠️ NOT CONFIGURED

**Required:**
- SSL certificate (Let's Encrypt or commercial)
- Web server configuration (OpenLiteSpeed/NGINX)
- HTTPS redirect (HTTP → HTTPS)
- HSTS headers

**See:** `PRODUCTION_PATCHING_GUIDE.md` - PATCH 44

---

### 3. Reverse Proxy Setup (PATCH 18)

**Status:** ⚠️ NOT CONFIGURED

**Required:**
- OpenLiteSpeed external processor
- Backend on 127.0.0.1:5555
- Proxy /api context
- CORS headers at proxy level

**See:** `PRODUCTION_PATCHING_GUIDE.md` - PATCH 18

---

## 🟢 MEDIUM PRIORITY - Configuration

### 4. Environment Variables

**Update `/Backend/.env` for production:**
```bash
NODE_ENV=production
EXPOSE_ERROR_DETAILS=false
ALLOW_CONCURRENT_SESSIONS=false
```

**Update `/Frontend/.env.production`:**
```bash
NEXT_PUBLIC_API_BASE_URL=https://your-domain.com/api
```

---

### 5. Frontend reCAPTCHA Integration

**Required Changes:**

1. **Add Google reCAPTCHA script to `_app.tsx` or `_document.tsx`:**
   ```html
   <script src="https://www.google.com/recaptcha/enterprise.js" async defer></script>
   ```

2. **Create reCAPTCHA hook (`useRecaptcha.ts`):**
   ```typescript
   export const useRecaptcha = () => {
     const executeRecaptcha = async (action: string) => {
       if (!window.grecaptcha?.enterprise) {
         throw new Error('reCAPTCHA not loaded');
       }

       const token = await window.grecaptcha.enterprise.execute(
         process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY,
         { action }
       );

       return token;
     };

     return { executeRecaptcha };
   };
   ```

3. **Update login page to include reCAPTCHA:**
   ```typescript
   const handleLogin = async (e) => {
     e.preventDefault();

     // Execute reCAPTCHA
     const recaptchaToken = await executeRecaptcha('LOGIN');

     // Include token in login request
     const response = await fetch('/api/auth/login', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({
         identifier,
         password,
         recaptchaToken  // ← Include token
       })
     });
   };
   ```

4. **Add environment variable:**
   ```bash
   # Frontend/.env.local
   NEXT_PUBLIC_RECAPTCHA_SITE_KEY=6LduqwEsAAAAAKlnlc0xFDUEvMrwNy6lxls37b3x
   ```

---

## Testing Checklist

### Before Production Deployment:

- [ ] reCAPTCHA enforcement enabled
- [ ] Frontend sends reCAPTCHA token on login
- [ ] Login fails without valid reCAPTCHA token
- [ ] Google Cloud credentials configured
- [ ] HTTPS/TLS certificate installed and working
- [ ] HTTP → HTTPS redirect active
- [ ] Reverse proxy configured
- [ ] Backend not accessible on direct port
- [ ] All environment variables set for production
- [ ] Error details not exposed (EXPOSE_ERROR_DETAILS=false)
- [ ] Security headers present (HSTS, X-Frame-Options, etc.)
- [ ] Rate limiting working correctly
- [ ] Session management tested
- [ ] All 57 patches verified in production environment

---

## Documentation References

- **PRODUCTION_PATCHING_GUIDE.md** - Infrastructure setup guide
- **FINAL_PATCH_SUMMARY.md** - Complete vulnerability status
- **DEV_PATCHING_PROGRESS.md** - Development patches applied

---

**Last Updated:** 2025-11-11  
**Priority:** CRITICAL  
**Estimated Time to Complete:** 6-8 hours  
**Risk Level if Deployed Without Fixes:** 🔴 CRITICAL
