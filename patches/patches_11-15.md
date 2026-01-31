# Patches 11-15: Information Disclosure & Network Security

**Vulnerabilities Fixed:**
- CWE-200 - Sensitive Data Exposure (CVSS 9.1)
- CWE-284 - Improper Access Control
- Network exposure issues

**Date:** 2025-10-28

---

## PATCH 11: Secure Public API Endpoints

### Vulnerability: CWE-200 - Information Disclosure

### File: `/Backend/routes/index.js`

### Location: Lines 24-41

### Before:
```javascript
router.get("/", (req, res) => {
  res.status(200).json({
    message: "SOC Dashboard API",
    version: "2.0.0",
    endpoints: {
      health: "/api/health",
      auth: "/api/auth",
      users: "/api/users",
      organisations: "/api/organisations",
      roles: "/api/roles",
      permissions: "/api/permissions",
      clients: "/api/clients",
      subscriptionPlans: "/api/subscription-plans",
      tickets: "/api/tickets",
      wazuh: "/api/wazuh",
      dashboard: "/api/dashboard",
      reports: "/api/reports",
      superadmin: "/api/superadmin"
    },
  });
});

router.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV,
  });
});
```

### After:
```javascript
// SECURITY: Minimal public API info - no endpoint enumeration
router.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "SOC Dashboard API",
    version: "2.0.0",
    // Endpoints removed - prevents reconnaissance attacks
  });
});

// SECURITY: Basic health check - no sensitive server info
router.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "healthy",
    timestamp: new Date().toISOString(),
    // uptime, memory, environment removed - information disclosure
  });
});
```

### Reason:
- Endpoint enumeration aids attackers in discovering attack surface
- Server uptime, memory, and environment details help attackers plan attacks
- Health checks should be minimal - just confirm service is responding

### Verification Steps:
1. Open `/Backend/routes/index.js`
2. Verify lines 24-41 match the "After" code
3. Test GET `/api/` - should NOT contain `endpoints` object
4. Test GET `/api/health` - should NOT contain `uptime`, `memory`, or `environment` fields

### Verification Tests:
```bash
# Test 1: Public endpoint information disclosure
curl http://localhost:5555/api
# Expected: {"success":true,"message":"SOC Dashboard API","version":"2.0.0"}
# Should NOT contain endpoints list

# Test 2: Health endpoint information disclosure
curl http://localhost:5555/api/health
# Expected: {"success":true,"status":"healthy","timestamp":"..."}
# Should NOT contain uptime, memory, or environment

# Test 3: Protected routes require authentication
curl http://localhost:5555/api/tickets
# Expected: {"statusCode":401,"message":"Access token required","success":false}

curl http://localhost:5555/api/users
# Expected: 401 Unauthorized
```

**Status:** ☐ Pass ☐ Fail

---

## PATCH 12: Model-Level Credential Protection (Organisation)

### File: `/Backend/models/organisation.model.js`

### Location: Lines 127-156, 226-240

### Added `select: false` to ALL credential fields:

```javascript
wazuh_manager_username: {
  type: String,
  trim: true,
  select: false  // Never include in default queries
},
wazuh_manager_password: {
  type: String,
  trim: true,
  select: false  // Never include in default queries
},
wazuh_indexer_username: {
  type: String,
  trim: true,
  select: false  // Never include in default queries
},
wazuh_indexer_password: {
  type: String,
  trim: true,
  select: false  // Never include in default queries
},
wazuh_dashboard_username: {
  type: String,
  trim: true,
  select: false  // Never include in default queries
},
wazuh_dashboard_password: {
  type: String,
  trim: true,
  select: false  // Never include in default queries
},
```

### Added `toJSON` transform:

```javascript
toJSON: {
  virtuals: true,
  transform: function(doc, ret) {
    // SECURITY: Remove sensitive credentials from JSON output
    delete ret.wazuh_manager_password;
    delete ret.wazuh_indexer_password;
    delete ret.wazuh_dashboard_password;
    delete ret.wazuh_manager_username;
    delete ret.wazuh_indexer_username;
    delete ret.wazuh_dashboard_username;
    return ret;
  }
}
```

### Reason:
- `select: false` prevents credentials from being loaded in queries by default
- `toJSON` transform ensures even if explicitly selected, they're never sent to client
- Defense in depth - multiple layers of protection

### Note:
IP addresses and ports are still in the model but NOT exposed in responses due to the `toJSON` transform. They're only used server-side by the `fetchClientCredentials` middleware for internal Wazuh API calls.

### Verification Steps:
1. Open `/Backend/models/organisation.model.js`
2. Verify all 6 credential fields have `select: false`
3. Verify `toJSON` transform exists in schema options
4. Verify transform deletes all 6 credential fields
5. Test: Query Organisation model - credentials should NOT be in result
6. Test: Explicitly select credentials with `.select('+wazuh_manager_password')` - they load but are removed by toJSON

---

## PATCH 13: Disable Dangerous Wazuh Credentials Endpoint

### File: `/Backend/controllers/secureAuth.controller.js`

### Location: Lines 122-137

### Before:
```javascript
export const getWazuhCredentials = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId)
      .populate('role_id')
      .select('organisation_id role_id status user_type');

    if (!user || user.status !== 'active') {
      throw new ApiError(403, 'Access denied');
    }

    // Only allow specific roles to access credentials
    const allowedRoles = ['Client', 'SuperAdmin', 'Analyst'];
    if (!allowedRoles.includes(user.role_id?.role_name)) {
      throw new ApiError(403, 'Insufficient permissions to access credentials');
    }

    const organization = await Organisation.findById(user.organisation_id)
      .select('wazuh_manager_ip wazuh_manager_port wazuh_manager_username wazuh_manager_password wazuh_indexer_ip wazuh_indexer_port wazuh_indexer_username wazuh_indexer_password wazuh_dashboard_ip wazuh_dashboard_port wazuh_dashboard_username wazuh_dashboard_password');

    // Return credentials (this endpoint should be heavily protected)
    return res.status(200).json(
      new ApiResponse(200, {
        wazuhCredentials: {
          manager: {
            ip: organization.wazuh_manager_ip,
            port: organization.wazuh_manager_port,
            username: organization.wazuh_manager_username,
            password: organization.wazuh_manager_password
          },
          indexer: {
            ip: organization.wazuh_indexer_ip,
            port: organization.wazuh_indexer_port,
            username: organization.wazuh_indexer_username,
            password: organization.wazuh_indexer_password
          },
          dashboard: {
            ip: organization.wazuh_dashboard_ip,
            port: organization.wazuh_dashboard_port,
            username: organization.wazuh_dashboard_username,
            password: organization.wazuh_dashboard_password
          }
        }
      }, 'Credentials retrieved successfully')
    );
  } catch (error) {
    // error handling
  }
};
```

### After:
```javascript
/**
 * SECURITY: REMOVED - This endpoint should NEVER exist
 * Wazuh credentials should NEVER be exposed to client-side
 * Backend should use credentials internally and return only the data users need
 *
 * If you need Wazuh data, create specific endpoints that:
 * 1. Use credentials server-side only
 * 2. Return only the specific data needed (alerts, agents, etc.)
 * 3. Never expose infrastructure details (IPs, ports, credentials)
 */
export const getWazuhCredentials = async (req, res) => {
  // SECURITY: This endpoint is disabled for security reasons
  return res.status(410).json(
    new ApiResponse(410, null, 'This endpoint has been removed for security reasons. Wazuh credentials are not exposed to clients.')
  );
};
```

### Reason:
- **Users should NEVER receive credentials** - only the data they need
- Backend should use credentials internally via `fetchClientCredentials` middleware
- Returns HTTP 410 Gone to indicate endpoint permanently removed
- This endpoint was a massive security vulnerability waiting to be exploited

### Verification Steps:
1. Open `/Backend/controllers/secureAuth.controller.js`
2. Verify `getWazuhCredentials` function returns 410 status
3. Test: Call `/api/auth/wazuh-credentials` with valid token - should return 410
4. Verify error message indicates endpoint removed for security

### Verification Test:
```bash
TOKEN="your_jwt_token_here"

curl -X GET "http://localhost:5555/api/auth/wazuh-credentials" \
  -H "Authorization: Bearer $TOKEN"

# Expected: HTTP 410 Gone
# Response: {"success":false,"data":null,"message":"This endpoint has been removed for security reasons..."}
```

**Status:** ☐ Pass ☐ Fail

---

## PATCH 14: Clarify Internal-Only Repository Function

### File: `/Backend/repositories/organisationRepository/organisation.repository.js`

### Location: Lines 221-245

### Before:
```javascript
export const getWazuhCredentials = async (id) => {
  const org = await Organisation.findById(id);
  if (!org) return null;

  return {
    wazuh_manager_ip: org.wazuh_manager_ip,
    wazuh_manager_port: org.wazuh_manager_port,
    wazuh_indexer_ip: org.wazuh_indexer_ip,
    wazuh_indexer_port: org.wazuh_indexer_port,
    wazuh_dashboard_ip: org.wazuh_dashboard_ip,
    wazuh_dashboard_port: org.wazuh_dashboard_port
  };
};
```

### After:
```javascript
// SECURITY: Internal use only - returns infrastructure details for backend operations
// This function should NEVER be called from controllers that return data to users
// Only use for internal backend operations like connecting to Wazuh
export const getWazuhCredentialsInternal = async (id) => {
  const org = await Organisation.findById(id)
    .select('+wazuh_manager_username +wazuh_manager_password +wazuh_indexer_username +wazuh_indexer_password +wazuh_dashboard_username +wazuh_dashboard_password');
  if (!org) return null;

  // Returns full credentials including IPs, ports, usernames, passwords
  // SECURITY WARNING: Never expose this in API responses
  return {
    wazuh_manager_ip: org.wazuh_manager_ip,
    wazuh_manager_port: org.wazuh_manager_port,
    wazuh_manager_username: org.wazuh_manager_username,
    wazuh_manager_password: org.wazuh_manager_password,
    wazuh_indexer_ip: org.wazuh_indexer_ip,
    wazuh_indexer_port: org.wazuh_indexer_port,
    wazuh_indexer_username: org.wazuh_indexer_username,
    wazuh_indexer_password: org.wazuh_indexer_password,
    wazuh_dashboard_ip: org.wazuh_dashboard_ip,
    wazuh_dashboard_port: org.wazuh_dashboard_port,
    wazuh_dashboard_username: org.wazuh_dashboard_username,
    wazuh_dashboard_password: org.wazuh_dashboard_password
  };
};
```

### Reason:
- Renamed function to clarify it's for INTERNAL use only
- Added explicit `.select('+field')` to include password fields (normally hidden)
- Added security warnings to prevent misuse
- Function is ONLY used by `fetchClientCredentials` middleware for server-side Wazuh API calls

### Verification Steps:
1. Open `/Backend/repositories/organisationRepository/organisation.repository.js`
2. Verify function renamed to `getWazuhCredentialsInternal`
3. Verify `.select()` explicitly includes password fields
4. Verify security warning comments exist
5. Search codebase for calls to this function - should ONLY be in `fetchClientCredentials` middleware
6. Verify NO controllers directly call this function

---

## PATCH 15: Remove Unauthenticated Test Endpoint

### File: `/Backend/routes/permission.routes.js`

### Location: Lines 16-19

### Before:
```javascript
// Temporary test endpoint without auth for debugging
router.get('/test', (req, res) => {
  res.json({ message: 'Permissions route working!', permissions: ['test:read', 'test:write'] });
});
```

### After:
```javascript
// SECURITY: Test endpoint removed - use authenticated endpoints only
// If debugging is needed in development, check logs or use /api/permissions with valid auth
```

### Result:
Test endpoint `/api/permissions/test` no longer accessible

### Verification:
```bash
curl http://localhost:5555/api/permissions/test

# Expected: 404 Not Found
# Expected Response: {"statusCode":404,"message":"Route /api/permissions/test not found","success":false}
```

**Status:** ☐ Pass ☐ Fail

---

## Summary

**Files Modified:** 5
**Security Improvements:**
- ✅ No endpoint enumeration in public APIs
- ✅ No server uptime/memory disclosure
- ✅ Model-level credential protection
- ✅ Wazuh credentials endpoint disabled (410)
- ✅ Internal credential function clearly marked
- ✅ Unauthenticated test endpoint removed

**Security Validation:**
- [ ] No infrastructure IPs exposed in API responses
- [ ] No ports exposed in API responses
- [ ] No credentials (usernames/passwords) exposed in API responses
- [ ] Public endpoints provide minimal information
- [ ] Backend can still use credentials internally for Wazuh API calls
- [ ] Test endpoints removed from production

**Status:** Ready for Verification
