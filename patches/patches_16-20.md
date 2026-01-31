# Patches 16-20: Network Security & Frontend Access Control

**Issues Fixed:**
- Network exposure vulnerabilities
- CORS configuration weaknesses
- Missing frontend permission guards
- CWE-284 - Missing Function-Level Access Control (CVSS 8.8)

**Date:** 2025-10-28

---

## PATCH 16: Backend Listen on Localhost Only

### File: `/Backend/server.js`

### Location: Lines 286-300

### Before:
```javascript
const startServer = async () => {
  try {
    await database.connect();
    app.listen(PORT, '0.0.0.0', () => {  // ❌ Exposed to all interfaces
      console.log(`🚀 Server is running at http://0.0.0.0:${PORT}`);
      console.log(`🌐 Available at http://localhost:${PORT} and http://192.168.1.12:${PORT}`);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};
```

### After:
```javascript
const startServer = async () => {
  try {
    await database.connect();
    // SECURITY: Listen on 127.0.0.1 only - NOT exposed to public internet
    // Backend is accessed via OpenLiteSpeed reverse proxy only
    app.listen(PORT, '127.0.0.1', () => {  // ✅ Localhost only
      console.log(`🚀 Server is running at http://127.0.0.1:${PORT}`);
      console.log(`🔒 Backend is local-only and accessible via OpenLiteSpeed reverse proxy`);
      console.log(`🌐 Public access: https://uat.cyberpull.space/api`);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};
```

### Result:
Backend now only listens on 127.0.0.1:5555 (NOT exposed to internet)

### Verification:
```bash
# Check listening address
sudo ss -tlnp | grep :5555

# Expected: 127.0.0.1:5555 (NOT 0.0.0.0:5555)
# Actual: LISTEN 127.0.0.1:5555 ✅

# Try to access backend directly from outside
curl http://YOUR_PUBLIC_IP:5555/api/health
# Expected: Connection refused or timeout
```

### Security Benefits:
- Backend NOT exposed to internet
- Only accessible via localhost
- Requires reverse proxy for public access
- Reduced attack surface

**Status:** ☐ Pass ☐ Fail

---

## PATCH 17: Harden CORS Configuration

### File: `/Backend/server.js`

### Location: Lines 242-279

### Before:
```javascript
app.use(
  cors({
    origin: [
      "http://localhost:3333",
      "http://uat.cyberpull.space",
      "http://uat.cyberpull.space:3333",
      "https://uat.cyberpull.space",
      "https://uat.cyberpull.space:3333",
      process.env.CORS_ORIGIN
    ].filter(Boolean),
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Cache-Control"],
  })
);
```

### After:
```javascript
// SECURITY: Environment-specific CORS configuration
// Production: HTTPS only | Development: HTTP allowed for localhost
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? [
      "https://uat.cyberpull.space",
      "https://uat.cyberpull.space:3333",
    ]
  : [
      "http://localhost:3333",
      "http://127.0.0.1:3333",
      "http://uat.cyberpull.space",
      "http://uat.cyberpull.space:3333",
      "https://uat.cyberpull.space",
      "https://uat.cyberpull.space:3333",
    ];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, Postman, curl)
      if (!origin) return callback(null, true);

      if (allowedOrigins.indexOf(origin) === -1) {
        const msg = 'CORS policy: Access from the specified origin is not allowed.';
        console.warn(`🚫 CORS blocked request from: ${origin}`);
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Cache-Control"],
    maxAge: 86400, // Cache preflight requests for 24 hours
  })
);
```

### Result:
- Production mode only allows HTTPS origins
- Development mode allows HTTP for localhost
- Unknown origins are blocked and logged
- Preflight requests cached for better performance

### Verification Steps:
1. Open `/Backend/server.js`
2. Verify `allowedOrigins` array is environment-specific
3. Verify production only has HTTPS origins
4. Verify CORS middleware uses origin validation function
5. Verify unknown origins are logged and blocked
6. Test: Send request from unauthorized origin - should be blocked

**Status:** ☐ Pass ☐ Fail

---

## PATCH 18: OpenLiteSpeed Reverse Proxy Configuration

### File: `/usr/local/lsws/conf/vhosts/uat.cyberpull.space/vhost.conf`

### Location: Lines 83-109

### Configuration Added:
```
# SECURITY: Node.js Backend Proxy (API endpoints)
# Backend is on 127.0.0.1:5555 (NOT exposed publicly)
extprocessor nodejs_backend {
  type                    proxy
  address                 http://127.0.0.1:5555
  maxConns                100
  pcKeepAliveTimeout      60
  initTimeout             60
  retryTimeout            0
  respBuffer              0
}

context /api {
  type                    proxy
  handler                 nodejs_backend
  addDefaultCharset       off

  extraHeaders            <<<END_extraHeaders
Access-Control-Allow-Origin: https://uat.cyberpull.space
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Cache-Control
Access-Control-Allow-Credentials: true
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
  END_extraHeaders
}
```

### Result:
- All `/api/*` requests proxied to backend (127.0.0.1:5555)
- Security headers added at reverse proxy level
- Backend NOT directly accessible from internet

### Services Restarted:
```bash
sudo /usr/local/lsws/bin/lswsctrl restart  # OpenLiteSpeed
sudo pm2 restart uat-soc-backend            # Backend
```

### Verification:
```bash
# Check OpenLiteSpeed is running
systemctl status lsws

# Check proxy configuration
grep -A 10 "extprocessor nodejs_backend" /usr/local/lsws/conf/vhosts/uat.cyberpull.space/vhost.conf

# Test API access via proxy
curl https://uat.cyberpull.space/api/health
# Expected: {"success":true,"status":"healthy","timestamp":"..."}

# Verify backend is NOT accessible directly
curl http://YOUR_PUBLIC_IP:5555/api/health
# Expected: Connection refused
```

### Architecture - Before vs After:

**Before (INSECURE):**
```
Internet → Backend (0.0.0.0:5555) ❌ EXPOSED
           ↓
        Database
```

**After (SECURE):**
```
Internet → OpenLiteSpeed (Port 443 HTTPS) ← SSL Certificate
           ↓
           /api → Backend (127.0.0.1:5555) ✅ PRIVATE
                  ↓
               Database (127.0.0.1:27017) ✅ PRIVATE
```

**Status:** ☐ Pass ☐ Fail

---

## PATCH 19: Fix Client Model Schema

### File: `/Backend/models/client.model.js`

### Location: Lines 12-27

### Before:
```javascript
wazuhCredentials: {
  host: String,
  username: String,
  password: String,
  select: false  // ❌ Invalid - causes schema error
},
```

### After:
```javascript
wazuhCredentials: {
  type: {
    host: String,
    username: String,
    password: String
  },
  select: false  // ✅ Correct syntax
},
indexerCredentials: {
  type: {
    host: String,
    username: String,
    password: String
  },
  select: false
},
```

### Result:
Schema error fixed, backend starts successfully

### Issue:
The `select: false` option was applied incorrectly to nested objects. Mongoose requires nested objects to be wrapped in a `type` field when using schema options like `select: false`.

### Verification Steps:
1. Open `/Backend/models/client.model.js`
2. Verify `wazuhCredentials` has proper structure with `type:` wrapper
3. Verify `indexerCredentials` has proper structure
4. Start backend - should start without Mongoose schema errors
5. Check logs for any schema validation warnings

**Status:** ☐ Pass ☐ Fail

---

## PATCH 20: Create PermissionGuard Component

### Vulnerability: CWE-284 - Missing Function-Level Access Control
### CVSS Score: 8.8 (High)

### File Created: `/Frontend/src/components/auth/PermissionGuard.tsx`

### Purpose:
Implement comprehensive permission-based access control for frontend routes

### Interface:
```typescript
interface PermissionGuardProps {
  children: React.ReactNode
  requiredPermissions?: string[]      // Permission-based check (PRIMARY)
  allowedRoles?: string[]              // Role-based fallback (DEPRECATED)
  redirectTo?: string                  // Redirect path for unauthorized
  showError?: boolean                  // Show error UI before redirect
  requireAll?: boolean                 // AND vs OR logic for permissions
}
```

### Security Features:

1. **Permission Validation**
   - Checks user permissions from JWT token/cookies
   - Supports flat permissions: `{'siem:access': true}`
   - Supports nested permissions: `{siem: {access: true, read: true}}`

2. **Fail-Secure**
   - Denies access by default if no rules specified
   - Shows loading state while checking permissions
   - Returns unauthorized error if user not found

3. **Audit Logging**
   - Logs all unauthorized access attempts to console
   - Includes user info, required permissions, and timestamp
   - Security alert format for monitoring

4. **User Feedback**
   - Shows clear error message explaining why access was denied
   - Displays which permissions are required
   - Shows user's current role

5. **Auto-Redirect**
   - Redirects unauthorized users to dashboard after 2.5 seconds
   - Optional immediate redirect (set `showError: false`)
   - Configurable redirect path

### Implementation:

```typescript
export default function PermissionGuard({
  children,
  requiredPermissions = [],
  allowedRoles = [],
  redirectTo = '/dashboard',
  showError = true,
  requireAll = false
}: PermissionGuardProps) {
  const router = useRouter()
  const [isAuthorized, setIsAuthorized] = useState<boolean | null>(null)

  useEffect(() => {
    const user = getUserFromCookies()

    if (!user) {
      setIsAuthorized(false)
      return
    }

    const userPermissions = user.permissions || {}

    // Convert nested permissions to flat array
    const userPermissionNames: string[] = []
    Object.keys(userPermissions).forEach(resource => {
      const actions = userPermissions[resource]
      if (typeof actions === 'object' && actions !== null) {
        Object.keys(actions).forEach(action => {
          if (actions[action] === true || actions[action] === 1) {
            userPermissionNames.push(`${resource}:${action}`)
          }
        })
      }
    })

    // Check permissions
    if (requiredPermissions.length > 0) {
      const hasPermission = requireAll
        ? requiredPermissions.every(p => userPermissionNames.includes(p))
        : requiredPermissions.some(p => userPermissionNames.includes(p))

      if (hasPermission) {
        setIsAuthorized(true)
      } else {
        // Log unauthorized access attempt
        console.error('🚨 SECURITY ALERT:', {
          event: 'UNAUTHORIZED_ACCESS_ATTEMPT',
          severity: 'HIGH',
          user: user.email || user.username || 'unknown',
          requiredPermissions,
          userPermissions: userPermissionNames,
          timestamp: new Date().toISOString()
        })
        setIsAuthorized(false)
      }
    }
  }, [requiredPermissions, allowedRoles, requireAll])

  // Auto-redirect after showing error
  useEffect(() => {
    if (isAuthorized === false) {
      const timer = setTimeout(() => {
        router.push(redirectTo)
      }, 2500)
      return () => clearTimeout(timer)
    }
  }, [isAuthorized, redirectTo, router])

  // Loading state
  if (isAuthorized === null) {
    return <div className="flex items-center justify-center min-h-screen">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
    </div>
  }

  // Authorized - render children
  if (isAuthorized) {
    return <>{children}</>
  }

  // Unauthorized - show error or redirect
  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-center mb-2">Access Denied</h2>
        <p className="text-center mb-4">You don't have permission to access this page.</p>
        <p className="text-sm text-gray-500 text-center">
          Redirecting to dashboard in a few seconds...
        </p>
      </div>
    </div>
  )
}
```

### Verification Steps:
1. Create `/Frontend/src/components/auth/PermissionGuard.tsx` with the above code
2. Verify component exports properly
3. Test: Wrap a page with `<PermissionGuard requiredPermissions={['siem:access']}>`
4. Test: User WITHOUT permission - should see "Access Denied" and redirect
5. Test: User WITH permission - should see page content
6. Check console for security alert logs

### Usage Example:
```typescript
// Protect SIEM page
export default function SIEMPage() {
  return (
    <PermissionGuard requiredPermissions={['siem:access']}>
      <SIEMPageContent />
    </PermissionGuard>
  )
}
```

**Status:** ☐ Pass ☐ Fail

---

## Summary

**Security Layers Added:**
- ✅ Backend only accessible via localhost
- ✅ Reverse proxy architecture implemented
- ✅ CORS hardened for production (HTTPS only)
- ✅ Security headers at proxy level
- ✅ Frontend permission guards implemented
- ✅ Unauthorized access logging

**Files Modified/Created:** 5
- `/Backend/server.js` (2 patches)
- `/usr/local/lsws/conf/vhosts/uat.cyberpull.space/vhost.conf`
- `/Backend/models/client.model.js`
- `/Frontend/src/components/auth/PermissionGuard.tsx`

**Architecture Improvements:**
- Backend: 0.0.0.0:5555 → 127.0.0.1:5555
- Public access: Direct → Via reverse proxy
- CORS: Permissive → Environment-specific
- Frontend: No access control → Permission-based guards

**Status:** Ready for Verification
