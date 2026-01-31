# Patches 1-5: Privilege Escalation & Access Control Fixes

**Vulnerability Fixed:** CWE-269 Vertical Privilege Escalation
**Risk Level:** Critical (9.8 CVSS)
**Date:** 2025-10-28

---

## PATCH 1: Remove Access Rules System (Tier-Based Access)

### Files Deleted:
```
/Backend/models/accessRule.model.js
/Backend/controllers/accessRuleController.js
/Backend/routes/accessRule.routes.js
/Backend/middlewares/dynamicTierAccess.middleware.js
```

### Files Modified to Remove References:
```
/Backend/routes/role.routes.js
/Backend/routes/permission.routes.js
/Backend/routes/client.routes.js
/Backend/routes/accessLevel.routes.js
```

### Changes:
- Removed import: `import { dynamicTierAccess } from '../middlewares/dynamicTierAccess.middleware.js';`
- Removed middleware from all routes: `dynamicTierAccess`

### Reason:
Access Rules provided a parallel authorization system that was confusing and unnecessary. All access control is now handled through the permission system.

### Verification Steps:
1. Check that files `/Backend/models/accessRule.model.js`, `/Backend/controllers/accessRuleController.js`, `/Backend/routes/accessRule.routes.js`, `/Backend/middlewares/dynamicTierAccess.middleware.js` are deleted
2. Search for `dynamicTierAccess` in all route files - should find 0 results
3. Search for `import.*accessRule` - should find 0 results

---

## PATCH 2: Remove Hardcoded Role Name Checks

### File: `/Backend/middlewares/authorization.middleware.js`

### Removed Code Pattern (EVERYWHERE):
```javascript
// BEFORE (VULNERABLE):
if (req.user.username == "superadmin") {
  return next();
}

if (req.user.role_id && req.user.role_id.role_name === "SuperAdmin") {
  return next();
}
```

### Lines Affected:
- Line 244 (organisationScope function)
- Line 280 (checkResourceOwnership function)
- Line 320 (requireRole function)
- Line 362 (requireFeature function)
- Line 413 (checkSubscriptionLimits function)
- Line 217 (authorizePermissions function)

### Result:
NO hardcoded role checks remain. All authorization is permission-based.

### Verification Steps:
1. Search `/Backend/middlewares/authorization.middleware.js` for `username == "superadmin"` - should find 0 results
2. Search for `role_name === "SuperAdmin"` - should find 0 results
3. Search for `role_name ==` - should find 0 results
4. Verify all authorization now uses `req.user.role_id?.permissions` checks

---

## PATCH 3: Permission-Based Organization Scope

### File: `/Backend/middlewares/organisationScope.middleware.js`

### Location: Lines 33-51

### Before:
```javascript
// Super admin bypass
if (allowSuperAdmin && req.user.is_super_admin) {
  return next();
}

// Internal users (like superadmin) should have access to all organizations
if (req.user.user_type === 'internal') {
  console.log('Internal user detected, allowing access');
  if (req.query.organisation_id) {
    req.organisationFilter = { organisation_id: req.query.organisation_id };
  }
  return next();
}
```

### After:
```javascript
// Check if user has permission to access all organisations
// Internal users with overview:read OR anyone with organisation:access:all
const hasOrgAccessAll = req.user.role_id?.permissions &&
  (req.user.role_id.permissions['organisation:access:all'] === true);

const hasOverviewRead = req.user.user_type === 'internal' &&
  req.user.role_id?.permissions &&
  (req.user.role_id.permissions['overview:read'] === true);

if (allowSuperAdmin && (hasOrgAccessAll || hasOverviewRead)) {
  console.log('User has permission to access all organisations');
  if (req.query.organisation_id) {
    req.organisationFilter = { organisation_id: req.query.organisation_id };
  }
  return next();
}
```

---

### File: `/Backend/middlewares/authorization.middleware.js` (organisationScope export)

### Location: Lines 242-251

### Before:
```javascript
if (req.user.username == "superadmin") {
  return next();
}
```

### After:
```javascript
const hasOrgAccessAll = req.user.role_id?.permissions &&
  (req.user.role_id.permissions['organisation:access:all'] === true);

const hasOverviewRead = req.user.user_type === 'internal' &&
  req.user.role_id?.permissions &&
  (req.user.role_id.permissions['overview:read'] === true);

if (hasOrgAccessAll || hasOverviewRead) {
  return next();
}
```

### Verification Steps:
1. Open `/Backend/middlewares/organisationScope.middleware.js`
2. Verify lines 33-51 match the "After" code
3. Open `/Backend/middlewares/authorization.middleware.js`
4. Verify lines 242-251 match the "After" code
5. Test: Internal user WITHOUT `overview:read` permission should NOT access all orgs
6. Test: Internal user WITH `overview:read` permission SHOULD access all orgs

---

## PATCH 4: Prevent Self-Role Modification

### File: `/Backend/services/user.service.new.js`

### Location: Lines 284-299

### Added Code:
```javascript
// SECURITY: Prevent self-role modification
if (updateData.role_id) {
  if (userId === updatedBy) {
    throw new ApiError(403, "You cannot modify your own role. Contact another administrator.");
  }

  // Validate role exists and is active
  const role = await findRoleById(updateData.role_id);
  if (!role || !role.is_active) {
    throw new ApiError(404, "Invalid or inactive role");
  }

  // Update role using dedicated function
  updatedUser = await updateUserRole(userId, updateData.role_id, updatedBy);
  delete updateData.role_id;
}
```

### Impact:
Users can NO LONGER escalate their own privileges by modifying their own role.

### Verification Steps:
1. Open `/Backend/services/user.service.new.js`
2. Verify lines 284-299 contain the self-role modification check
3. Verify the check: `if (userId === updatedBy)` exists
4. Test: Attempt to update own user record with different `role_id` - should return 403 error
5. Test: Admin updating ANOTHER user's role - should succeed

---

## PATCH 5: Field Whitelisting in User Repository

### File: `/Backend/repositories/userRepository/user.repository.js`

### Location: Lines 32-81

### Before:
```javascript
export const updateUserById = async (id, updatedFields, userId = null) => {
  if (userId) {
    updatedFields.updated_by = userId;
  }
  return await User.findByIdAndUpdate(id, updatedFields, {
    new: true,
    runValidators: true,
  });
};
```

### After:
```javascript
export const updateUserById = async (id, updatedFields, userId = null) => {
  // SECURITY: Whitelist allowed fields
  const allowedFields = [
    'full_name', 'phone_number', 'timezone', 'locale',
    'notification_preferences', 'avatar_url', 'status',
    'updated_by', 'last_login_at', 'last_activity_at',
    'last_login_ip', 'failed_login_attempts', 'locked_until',
    'must_change_password', 'two_factor_enabled', 'two_factor_secret',
    'backup_codes', 'is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason'
  ];

  // SECURITY: Restricted fields (handled by dedicated functions)
  const restrictedFields = ['role_id', 'organisation_id', 'username', 'email', 'password_hash', 'user_type'];

  // Filter out fields not in whitelist
  const filteredFields = {};
  for (const key in updatedFields) {
    if (allowedFields.includes(key)) {
      filteredFields[key] = updatedFields[key];
    } else if (restrictedFields.includes(key)) {
      console.warn(`[SECURITY] Attempted to update restricted field '${key}' via updateUserById`);
    }
  }

  if (userId) {
    filteredFields.updated_by = userId;
  }

  return await User.findByIdAndUpdate(id, filteredFields, {
    new: true,
    runValidators: true,
  });
};
```

### Impact:
Users can NO LONGER inject arbitrary fields like `role_id`, `organisation_id`, `password_hash`, etc. into update requests.

### Verification Steps:
1. Open `/Backend/repositories/userRepository/user.repository.js`
2. Verify lines 32-81 contain the field whitelisting logic
3. Verify `allowedFields` array is defined
4. Verify `restrictedFields` array includes: `role_id`, `organisation_id`, `username`, `email`, `password_hash`, `user_type`
5. Verify the filtering loop exists
6. Test: Send update request with `role_id` in body - should be silently ignored
7. Test: Send update request with `password_hash` - should be silently ignored
8. Check server logs for security warnings when restricted fields are attempted

---

## Required Permissions

| Permission | Description |
|------------|-------------|
| `organisation:access:all` | Access ALL organizations (not just own) |
| `overview:read` | Internal users with this can access all orgs |
| `user:update:all` | Update ANY user including role assignment |

---

## Verification Tests

### Test 1: Verify Self-Role Modification is Blocked

**Objective:** Confirm users cannot escalate their own privileges

**Steps:**
1. Log in as a regular user (not SuperAdmin)
2. Get your own user ID
3. Attempt to update your own role to a higher privilege role:
   ```bash
   PUT /api/users/{your_user_id}
   Headers: Authorization: Bearer {your_token}
   Body: {
     "role_id": "{superadmin_role_id}"
   }
   ```
4. **Expected Result:** 403 Forbidden with message: "You cannot modify your own role. Contact another administrator."

**Status:** ☐ Pass ☐ Fail

---

### Test 2: Verify Field Whitelisting Blocks Unauthorized Fields

**Objective:** Confirm malicious field injection is prevented

**Steps:**
1. Log in as any user
2. Attempt to inject restricted fields via user update:
   ```bash
   PUT /api/users/me/profile
   Headers: Authorization: Bearer {your_token}
   Body: {
     "full_name": "John Doe",
     "role_id": "{admin_role_id}",
     "password_hash": "malicious_hash",
     "organisation_id": "{other_org_id}"
   }
   ```
3. **Expected Result:** Update succeeds BUT only `full_name` is updated. Role, password_hash, and organisation_id are silently ignored.
4. Check server logs for security warnings

**Status:** ☐ Pass ☐ Fail

---

### Test 3: Verify Permission-Based Organization Access

**Objective:** Confirm hardcoded role checks are removed

**Steps:**
1. Create a test user with `overview:read` permission (internal user)
2. Create another test user WITHOUT `overview:read` (internal user)
3. Test User 1: Attempt to access `/api/organisations`
   - **Expected:** Can access all organizations
4. Test User 2: Attempt to access `/api/organisations`
   - **Expected:** Can only access their own organization

**Status:** ☐ Pass ☐ Fail

---

### Test 4: Verify Hardcoded "superadmin" Username Check is Removed

**Objective:** Confirm username-based bypasses no longer work

**Steps:**
1. Create a regular user account
2. Change username to "superadmin" (via database or admin panel)
3. Attempt to access admin-only endpoints
4. **Expected Result:** Access DENIED (403 Forbidden) - username should have NO special privileges

**Status:** ☐ Pass ☐ Fail

---

## Summary

**Security Improvements:**
- ✅ No hardcoded role checks
- ✅ Permission-based authorization everywhere
- ✅ Field whitelisting prevents injection
- ✅ Self-role modification blocked
- ✅ Server-side validation on every request

**Files Modified:** 8
**Files Deleted:** 4
**Lines Changed:** ~200+

**Status:** Ready for Verification
