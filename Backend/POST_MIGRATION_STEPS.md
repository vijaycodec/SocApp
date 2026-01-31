# Post-Migration Steps for Permission Name Changes

## Issue
After running the permission migration script (`migrations/update-permissions-to-singular.js`), users who were logged in BEFORE the migration will have **stale permission data** in their browser cookies.

## Root Cause
When users log in, the backend:
1. Retrieves user data from the database
2. Includes permissions in the JWT token and response
3. Frontend stores this user data in cookies (`user_info` cookie)

When the permission names were changed from plural to singular in the database:
- `users:read` → `user:read`
- `roles:read` → `role:read`
- `permissions:read` → `permission:read`

Users who were already logged in still have the OLD permission names in their cookies, causing permission checks to fail.

## Symptoms
- User gets "Access Denied" errors even though they have the correct permissions in the database
- Console shows: `🚫 PermissionGuard: Access denied. Required: ['user:read'] User has: ['users:read']`
- Database check confirms user has correct singular permission names

## Solution

### For All Users:
**All users MUST log out and log back in after the migration is complete.**

This will:
1. Clear old cookies with plural permission names
2. Fetch fresh user data from database with singular permission names
3. Store updated permissions in new cookies

### Steps:
1. **Announce Maintenance Window**: Notify all users to log out
2. **Run Migration Script**:
   ```bash
   node migrations/update-permissions-to-singular.js
   ```
3. **Verify Migration**:
   ```bash
   node check-permissions.js
   ```
4. **Force Logout (Optional but Recommended)**:
   - Clear all user sessions from database
   ```javascript
   // In MongoDB shell or create a script:
   db.user_sessions.deleteMany({})
   ```
5. **Notify Users**: Ask all users to log in again

### For Individual Users:
If a specific user is experiencing issues:

1. Ask them to:
   - Log out completely
   - Clear browser cache/cookies (optional but recommended)
   - Log back in

2. Or clear their session server-side:
   ```javascript
   // Backend script or admin action
   await UserSession.deleteMany({ user_id: userId })
   ```

## Verification

After users log back in, they should see in browser console (F12 → Console):
```
✅ PermissionGuard: Access granted - user has required permissions
User Permissions: ['user:read', 'user:create', 'role:read', 'role:create', ...]
```

NOT:
```
🚫 PermissionGuard: Access denied. Required: ['user:read'] User has: ['users:read']
```

## Prevention

To prevent similar issues in future migrations:

1. **Always run migrations during maintenance windows**
2. **Notify users to log out before migrations**
3. **Consider auto-logout**: Add a feature to invalidate all sessions when critical data changes
4. **Version tokens**: Include a "permission schema version" in JWT tokens to automatically detect stale data

## Related Files
- Migration script: `Backend/migrations/update-permissions-to-singular.js`
- Verification script: `Backend/check-permissions.js`
- Frontend auth: `Frontend/src/lib/auth.ts`
- Permission guard: `Frontend/src/components/auth/PermissionGuard.tsx`
- Backend login: `Backend/services/auth.service.new.js`

## Date
Created: 2025-12-03
Migration: Plural → Singular Permission Names
