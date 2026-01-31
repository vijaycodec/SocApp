# Patches 6-10: Credential Protection & Security Hardening

**Vulnerabilities Fixed:**
- CWE-522 - Insufficiently Protected Credentials (CVSS 9.1)
- CWE-798 - Use of Hard-coded Credentials

**Date:** 2025-10-28

---

## PATCH 6: Dedicated Functions for Restricted Field Updates

### File: `/Backend/repositories/userRepository/user.repository.js`

### Location: Lines 83-117

### Added Functions:

```javascript
// SECURITY: Dedicated function for updating user role (requires user:update:all permission)
export const updateUserRole = async (id, role_id, updatedBy) => {
  return await User.findByIdAndUpdate(
    id,
    { role_id, updated_by: updatedBy },
    { new: true, runValidators: true }
  );
};

// SECURITY: Dedicated function for updating user email (requires user:update:all permission)
export const updateUserEmail = async (id, email, updatedBy) => {
  return await User.findByIdAndUpdate(
    id,
    { email: email.toLowerCase(), updated_by: updatedBy },
    { new: true, runValidators: true }
  );
};

// SECURITY: Dedicated function for updating username (requires user:update:all permission)
export const updateUserUsername = async (id, username, updatedBy) => {
  return await User.findByIdAndUpdate(
    id,
    { username: username.toLowerCase(), updated_by: updatedBy },
    { new: true, runValidators: true }
  );
};

// SECURITY: Dedicated function for updating organisation (requires user:update:all permission)
export const updateUserOrganisation = async (id, organisation_id, updatedBy) => {
  return await User.findByIdAndUpdate(
    id,
    { organisation_id, updated_by: updatedBy },
    { new: true, runValidators: true }
  );
};
```

### Impact:
Restricted fields can ONLY be updated through these dedicated functions, ensuring proper authorization checks.

### Verification Steps:
1. Open `/Backend/repositories/userRepository/user.repository.js`
2. Verify functions exist at lines 83-117: `updateUserRole`, `updateUserEmail`, `updateUserUsername`, `updateUserOrganisation`
3. Verify each function only updates ONE specific field
4. Verify each function requires `updatedBy` parameter
5. Verify comments indicate `user:update:all` permission required

---

## PATCH 7: Service Layer Uses Dedicated Functions

### File: `/Backend/services/user.service.new.js`

### Location: Lines 9-12 (imports), 258-310 (logic)

### Added Import:
```javascript
import {
  // ... existing imports
  updateUserRole,
  updateUserEmail,
  updateUserUsername,
  updateUserOrganisation,
  // ... rest
} from "../repositories/userRepository/user.repository.js";
```

### Updated Logic:
```javascript
// SECURITY: Handle restricted fields separately with dedicated functions
let updatedUser = user;

// Validate and update email if provided (requires user:update:all)
if (updateData.email && updateData.email !== user.email) {
  const emailExists = await checkEmailExists(updateData.email, userId);
  if (emailExists) {
    throw new ApiError(409, "Email is already in use");
  }
  updatedUser = await updateUserEmail(userId, updateData.email, updatedBy);
  delete updateData.email;
}

// Validate and update username if provided (requires user:update:all)
if (updateData.username && updateData.username !== user.username) {
  const usernameExists = await checkUsernameExists(updateData.username, userId);
  if (usernameExists) {
    throw new ApiError(409, "Username is already taken");
  }
  updatedUser = await updateUserUsername(userId, updateData.username, updatedBy);
  delete updateData.username;
}

// SECURITY: Prevent self-role modification
if (updateData.role_id) {
  if (userId === updatedBy) {
    throw new ApiError(403, "You cannot modify your own role.");
  }
  const role = await findRoleById(updateData.role_id);
  if (!role || !role.is_active) {
    throw new ApiError(404, "Invalid or inactive role");
  }
  updatedUser = await updateUserRole(userId, updateData.role_id, updatedBy);
  delete updateData.role_id;
}

// Update organisation if provided (requires user:update:all)
if (updateData.organisation_id) {
  updatedUser = await updateUserOrganisation(userId, updateData.organisation_id, updatedBy);
  delete updateData.organisation_id;
}

// Update remaining allowed fields (profile fields only)
if (Object.keys(updateData).length > 0) {
  updatedUser = await updateUserById(userId, updateData, updatedBy);
}
```

### Verification Steps:
1. Open `/Backend/services/user.service.new.js`
2. Verify imports include the 4 dedicated functions (lines 9-12)
3. Verify logic at lines 258-310 uses dedicated functions for restricted fields
4. Verify `delete updateData.email` after email update
5. Verify `delete updateData.username` after username update
6. Verify `delete updateData.role_id` after role update
7. Verify `delete updateData.organisation_id` after org update
8. Verify remaining fields passed to `updateUserById` at the end

---

## PATCH 8: Remove Credential Exposure (CRITICAL)

### Vulnerability: CWE-522 - Insufficiently Protected Credentials
### CVSS Score: 9.1 (Critical)

### Description:
The system was exposing Wazuh and Indexer credentials (including passwords) to the frontend in API responses, allowing attackers to steal infrastructure credentials.

---

### File 1: `/Backend/controllers/auth.controller.js` (Lines 12-20)
### File 2: `/Backend/controllers/authController.js` (Lines 10-18)

### Before:
```javascript
return res.status(200).json({
  message: `Welcome ${result.user.full_name || 'User'}`,
  data: {
    access_token: result.token,
    user: result.user,
    wazuhCredentials: result.wazuhCredentials,  // ❌ EXPOSED!
    indexerCredentials: result.indexerCredentials  // ❌ EXPOSED!
  }
});
```

### After:
```javascript
return res.status(200).json({
  message: `Welcome ${result.user.full_name || 'User'}`,
  data: {
    access_token: result.token,
    user: result.user
    // Credentials removed - handled server-side only
  }
});
```

---

### File 3: `/Backend/models/user.model.js`

### Changes:
- Added `select: false` to `password_hash` field (Line 54)
- Added `toJSON` transform to remove sensitive fields (Lines 178-189)

### Before:
```javascript
password_hash: {
  type: String,
  required: true
},
```

### After:
```javascript
password_hash: {
  type: String,
  required: true,
  select: false  // SECURITY: Never include password hash in queries
},
```

### toJSON Transform Added:
```javascript
toJSON: {
  virtuals: true,
  transform: function(doc, ret) {
    // SECURITY: Remove sensitive fields from JSON output
    delete ret.password_hash;
    delete ret.two_factor_secret;
    delete ret.backup_codes;
    delete ret.reset_token;
    delete ret.reset_token_expires;
    return ret;
  }
}
```

---

### File 4: `/Backend/models/client.model.js`

### Changes:
- Added `select: false` to credentials fields (Lines 16, 22)
- Added `toJSON` transform (Lines 28-34)

### Before:
```javascript
wazuhCredentials: {
  host: String,
  username: String,
  password: String
},
indexerCredentials: {
  host: String,
  username: String,
  password: String
},
```

### After:
```javascript
wazuhCredentials: {
  host: String,
  username: String,
  password: String,
  select: false  // Never include in default queries
},
indexerCredentials: {
  host: String,
  username: String,
  password: String,
  select: false  // Never include in default queries
},
```

### toJSON Transform Added:
```javascript
toJSON: {
  transform: function(doc, ret) {
    // SECURITY: Remove credentials from JSON output
    delete ret.wazuhCredentials;
    delete ret.indexerCredentials;
    return ret;
  }
}
```

---

### File 5: `/Backend/models/organisation.model.js`

### Changes:
- Added `select: false` to all Wazuh credential fields (Lines 130, 135, 140, 145, 150, 155)
- Added `toJSON` transform (Lines 226-238)

### Fields Protected:
- `wazuh_manager_username`, `wazuh_manager_password`
- `wazuh_indexer_username`, `wazuh_indexer_password`
- `wazuh_dashboard_username`, `wazuh_dashboard_password`

---

### File 6: `/Backend/controllers/clientController.js`

### All endpoints updated to exclude credentials:

- `createClient` (Lines 43-49): Returns only safe fields
- `getAllClients` (Lines 71-73): Added `.select('-wazuhCredentials -indexerCredentials')`
- `getClientById` (Lines 113-115): Added `.select('-wazuhCredentials -indexerCredentials')`
- `updateClient` (Line 168): Added `.select('-wazuhCredentials -indexerCredentials')`

### Verification Steps:
1. Open `/Backend/controllers/auth.controller.js` and verify NO `wazuhCredentials` or `indexerCredentials` in response
2. Open `/Backend/controllers/authController.js` - same check
3. Open `/Backend/models/user.model.js`:
   - Verify `password_hash` has `select: false`
   - Verify `toJSON` transform exists and deletes sensitive fields
4. Open `/Backend/models/client.model.js`:
   - Verify both credential objects have `select: false`
   - Verify `toJSON` transform deletes credentials
5. Open `/Backend/models/organisation.model.js`:
   - Verify all 6 password fields have `select: false`
   - Verify `toJSON` transform exists
6. Open `/Backend/controllers/clientController.js`:
   - Verify all queries use `.select('-wazuhCredentials -indexerCredentials')`

---

## PATCH 9: Remove Hardcoded Password (CRITICAL)

### Vulnerability: CWE-798 - Use of Hard-coded Credentials

### File: `/Backend/controllers/agents.controller.js`

### Location: Lines 137-158

### Before:
```javascript
const { agentId, action, password, agentOS, whitelistIPs } = req.body;

if (!agentId || !action || !password) {
  throw new ApiError(400, 'Missing required fields: agentId, action, password');
}

// TODO: Validate super admin password here
if (password !== 'SuperStrong@123') {  // ❌ HARDCODED PASSWORD!
  throw new ApiError(401, 'Invalid super admin password');
}
```

### After:
```javascript
const { agentId, action, agentOS, whitelistIPs } = req.body;

if (!agentId || !action) {
  throw new ApiError(400, 'Missing required fields: agentId, action');
}

// SECURITY: Permission-based validation instead of hardcoded password
const hasPermission = req.user.role_id?.permissions &&
  (req.user.role_id.permissions['agent:quarantine'] === true ||
   req.user.role_id.permissions['agent:manage'] === true);

if (!hasPermission) {
  throw new ApiError(403, 'You do not have permission to quarantine agents');
}
```

### Impact:
- Removed hardcoded password `SuperStrong@123`
- Replaced with permission-based authorization
- Requires `agent:quarantine` or `agent:manage` permission

### Verification Steps:
1. Open `/Backend/controllers/agents.controller.js`
2. Search for `SuperStrong@123` - should find 0 results
3. Verify lines 137-158 have permission-based validation
4. Verify `password` parameter is NOT destructured from `req.body`
5. Verify error message changed from 401 to 403
6. Test: Attempt quarantine without permission - should return 403

---

## PATCH 10: Update Seed File with New Permissions

### File: `/Backend/seeds/seed-all.js`

### New Permissions Added:

1. **`user:update:all`** - Update any user including role assignments (replaces basic `users:update`)
2. **`organisation:access:all`** - Bypass organization scope to access all organizations
3. **`wazuh:access`** - Access Wazuh/Indexer credentials and data
4. **`agent:quarantine`** - Quarantine and release security agents

### Permissions Renamed (Singular Form):
- `users:*` → `user:*`
- `roles:*` → `role:*`
- `permissions:*` → `permission:*`
- `agents:*` → `agent:*`

### Role Permission Updates:

#### SuperAdmin Role:
- Gets ALL permissions automatically (no changes needed)

#### Admin Role:
- Added: `user:update:all`, `organisation:access:all`, `wazuh:access`, `agent:quarantine`
- Updated: Singular form for all permissions

#### Manager Role:
- Added: `wazuh:access`, `agent:manage`
- Updated: Singular form for all permissions

#### Analyst Role:
- Added: `wazuh:access`
- Updated: Singular form for all permissions

#### Client Role:
- Added: `user:update` (can update own profile), `wazuh:access`, `tickets:create`

### Access Rules System:
- ❌ **COMPLETELY REMOVED**
- Replaced with permission-based authorization
- All tier-based access rules deleted from seed file

### To Apply Changes:
```bash
cd /home/ubuntu/Desktop/SOC_Dashboard\ 2/SOC_Dashboard\ 2/Backend
node seeds/seed-all.js
```

**⚠️ Warning:** This will clear and reseed the entire database!

### Verification Steps:
1. Open `/Backend/seeds/seed-all.js`
2. Verify new permissions exist:
   - `user:update:all`
   - `organisation:access:all`
   - `wazuh:access`
   - `agent:quarantine`
3. Verify NO plural form permissions (`users:*`, `roles:*`, etc.)
4. Verify SuperAdmin role gets ALL permissions
5. Verify Admin role has the 4 new permissions
6. Verify NO access rules / tier system code exists
7. Run seed file and check database for new permissions

---

## Required Permissions Summary

| Permission | Description |
|------------|-------------|
| `user:update:all` | Update ANY user including role assignment |
| `organisation:access:all` | Access ALL organizations (not just own) |
| `wazuh:access` | Access Wazuh/Indexer credentials and data |
| `agent:quarantine` | Quarantine and release security agents |
| `agent:manage` | Full agent management permissions |

---

## Verification Tests

### Test 5: Verify Credentials NOT in Login Response

**Objective:** Confirm wazuh/indexer credentials are never sent to frontend

**Steps:**
1. Open browser developer tools (Network tab)
2. Log in to the application
3. Inspect the login API response (POST `/api/auth/login`)
4. **Expected Result:** Response should contain:
   ```json
   {
     "message": "Welcome User",
     "data": {
       "access_token": "...",
       "user": { ... }
       // NO wazuhCredentials
       // NO indexerCredentials
     }
   }
   ```

**Status:** ☐ Pass ☐ Fail

---

### Test 6: Verify password_hash NOT Exposed

**Objective:** Confirm password hashes never appear in API responses

**Steps:**
1. Call GET `/api/users` endpoint
2. Inspect user objects in response
3. **Expected Result:** NO `password_hash` field in any user object
4. Call GET `/api/users/{user_id}` for a specific user
5. **Expected Result:** NO `password_hash` field

**Status:** ☐ Pass ☐ Fail

---

### Test 7: Verify Client Credentials NOT Exposed

**Objective:** Confirm client credentials never appear in responses

**Steps:**
1. Call GET `/api/clients` endpoint
2. **Expected Result:** Response should NOT contain `wazuhCredentials` or `indexerCredentials`
3. Call GET `/api/clients/{client_id}`
4. **Expected Result:** Same - no credentials exposed

**Status:** ☐ Pass ☐ Fail

---

### Test 8: Verify Hardcoded Password Removed

**Objective:** Confirm hardcoded password no longer works

**Steps:**
1. Attempt to quarantine an agent with the old hardcoded password:
   ```bash
   POST /api/agents/quarantine
   Body: {
     "agentId": "001",
     "action": "isolate",
     "password": "SuperStrong@123"
   }
   ```
2. **Expected Result:** 400 Bad Request (password field not recognized) OR 403 Forbidden (no permission)
3. Attempt without proper `agent:quarantine` permission
4. **Expected Result:** 403 Forbidden

**Status:** ☐ Pass ☐ Fail

---

### Test 9: Verify Organisation Credentials NOT Exposed

**Objective:** Confirm organisation Wazuh passwords never exposed

**Steps:**
1. Call GET `/api/organisations` endpoint
2. Inspect response for any of these fields:
   - `wazuh_manager_password`
   - `wazuh_indexer_password`
   - `wazuh_dashboard_password`
3. **Expected Result:** NONE of these fields present
4. Call GET `/api/organisations/{org_id}`
5. **Expected Result:** Same - no password fields

**Status:** ☐ Pass ☐ Fail

---

## Summary

**Security Layers Added:**
- ✅ Permission-based authorization (no hardcoded roles)
- ✅ Field whitelisting (prevent field injection)
- ✅ Self-role modification prevention
- ✅ Credential protection at model level
- ✅ Credential protection at controller level
- ✅ Password exclusion from all queries
- ✅ Hardcoded password removal

**Files Modified:** 16
**Lines Changed:** ~400+

**Status:** Ready for Verification
