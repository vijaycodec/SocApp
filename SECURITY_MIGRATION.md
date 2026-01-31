# 🔐 Security Migration Guide

## Current Security Issues

### ❌ **Critical Issues Found:**
1. **JWT tokens stored in localStorage** - Accessible via XSS attacks
2. **User permissions in cookies** - Client-accessible, can be manipulated
3. **Organization data in localStorage** - Contains sensitive business info
4. **Wazuh credentials exposed** - Host details and potentially credentials visible
5. **Long-lived tokens** - No proper token refresh mechanism

## 🛡️ Secure Storage Strategy

### **Data Classification:**

#### **🔴 CRITICAL (Never store client-side):**
- JWT tokens with sensitive claims
- Wazuh credentials (usernames, passwords, IPs)
- Detailed user permissions
- Organization internal details

#### **🟡 SENSITIVE (Limited client-side storage):**
- Basic user info (name, email, role)
- Organization display names (for UI only)
- Non-sensitive preferences

#### **🟢 SAFE (OK for client-side):**
- UI preferences (theme, language)
- Non-sensitive cached data
- Public configuration

## 📋 Implementation Plan

### **Phase 1: Immediate Security Fixes**

#### **1. Move to Secure Token Storage**
```typescript
// ❌ Current (INSECURE)
localStorage.setItem('token', token)
Cookies.set('auth_token', token)

// ✅ New (SECURE)
sessionStorage.setItem('access_token', shortLivedToken) // Max 1 hour
// Refresh token in HTTPOnly cookie (set by server)
```

#### **2. Remove Permissions from Client Storage**
```typescript
// ❌ Current (INSECURE)
Cookies.set('user_info', JSON.stringify({
  permissions: { admin: true, read: true } // Exploitable!
}))

// ✅ New (SECURE)
// Fetch permissions server-side when needed
const permissions = await fetchUserPermissions()
```

#### **3. Secure Organization Data**
```typescript
// ❌ Current (INSECURE)
localStorage.setItem('selectedClient', JSON.stringify({
  wazuhHost: 'internal-ip:9200', // Exposed!
  credentials: { ... } // Dangerous!
}))

// ✅ New (SECURE)
// Only store display name, fetch details server-side
sessionStorage.setItem('org_display', 'Organization Name')
```

### **Phase 2: Backend Security Endpoints**

#### **Created Secure Endpoints:**
- `GET /api/auth/permissions` - Fetch permissions server-side
- `GET /api/auth/organization` - Get organization details securely
- `GET /api/auth/wazuh-credentials` - Highly restricted credential access
- `POST /api/auth/refresh` - Token refresh mechanism

### **Phase 3: Frontend Migration**

#### **New Secure Auth Module** (`src/lib/secureAuth.ts`):
```typescript
// Minimal client-side storage
interface PublicUserInfo {
  id: string
  email: string
  full_name: string
  role: string // Basic role only
}

// Secure methods
setSecureAuthSession(publicInfo, tokens)
getPublicUserInfo()
fetchUserPermissions() // Server call
fetchUserOrganization() // Server call
```

## 🚀 Migration Steps

### **Step 1: Update Authentication Flow**

1. **Update login service** to return minimal user data
2. **Implement HTTPOnly cookies** for refresh tokens
3. **Use sessionStorage** for short-lived access tokens

### **Step 2: Replace Permission Checks**

```typescript
// ❌ Old way (client-side check)
const user = getUserFromCookies()
if (user.permissions?.admin?.read) {
  // Show admin content
}

// ✅ New way (server-side validation)
const hasPermission = await checkPermission('admin.read')
if (hasPermission) {
  // Show admin content
}
```

### **Step 3: Secure Organization Handling**

```typescript
// ❌ Old way
const client = JSON.parse(localStorage.getItem('selectedClient'))
const wazuhUrl = `https://${client.wazuhHost}`

// ✅ New way
const orgInfo = await fetchUserOrganization()
const wazuhUrl = orgInfo.dashboardUrl // Safe, pre-validated URL
```

### **Step 4: Update Components**

1. **Header Component** - Use secure organization fetching
2. **Dashboard Components** - Fetch permissions on-demand
3. **Settings Pages** - Server-side permission validation

## 🔧 Configuration Changes

### **Environment Variables (Add these):**

```env
# Token Security
JWT_ACCESS_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d
JWT_REFRESH_SECRET=your-refresh-secret

# Cookie Security
COOKIE_SECURE=true
COOKIE_SAME_SITE=strict
COOKIE_HTTP_ONLY=true

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_CREDENTIALS_MAX=20
```

### **Server Configuration:**

```javascript
// Cookie options for secure tokens
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
}

res.cookie('refreshToken', refreshToken, cookieOptions)
```

## ⚠️ Breaking Changes

### **Frontend Changes Required:**

1. **Update all permission checks** to use server-side validation
2. **Replace direct cookie/localStorage access** with secure methods
3. **Update organization context** to use secure fetching
4. **Implement token refresh logic** for expired access tokens

### **Backend Changes Required:**

1. **Add secure auth routes** (`/api/auth/permissions`, etc.)
2. **Update JWT token creation** to exclude sensitive data
3. **Implement HTTPOnly refresh tokens**
4. **Add rate limiting** to sensitive endpoints

## 🧪 Testing Security

### **Security Tests to Implement:**

```javascript
// Test 1: Verify no sensitive data in client storage
test('No sensitive data in localStorage', () => {
  const keys = Object.keys(localStorage)
  keys.forEach(key => {
    const value = localStorage.getItem(key)
    expect(value).not.toContain('password')
    expect(value).not.toContain('credentials')
    expect(value).not.toContain('secret')
  })
})

// Test 2: Verify HTTPOnly cookies
test('Refresh token is HTTPOnly', () => {
  // Cannot access via document.cookie if HTTPOnly
  expect(document.cookie).not.toContain('refreshToken')
})
```

## 📊 Security Improvements Achieved

✅ **XSS Attack Resistance** - No sensitive data accessible via JavaScript
✅ **CSRF Protection** - HTTPOnly cookies with SameSite
✅ **Token Theft Prevention** - Short-lived access tokens
✅ **Privilege Escalation Prevention** - Server-side permission validation
✅ **Information Disclosure Prevention** - Minimal client-side data exposure

## 🔄 Rollback Plan

If issues arise during migration:

1. Keep old auth methods as fallback
2. Feature flags for new security measures
3. Gradual component migration
4. Monitoring for authentication errors

## 📝 Next Steps

1. **Review and approve** this security strategy
2. **Test secure auth endpoints** in development
3. **Gradually migrate components** to secure methods
4. **Monitor performance impact** of server-side permission checks
5. **Conduct security audit** after migration

---

**⚠️ WARNING:** This migration will require updating most authentication-related code. Plan for thorough testing and consider a phased rollout.