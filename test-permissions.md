# Permission Fix Test Instructions

## Problem Identified
The `getUserFromCookies()` function in `Frontend/src/lib/auth.ts` was using stale permissions from the `user_info` cookie instead of the fresh permissions from the JWT token.

## Fix Applied
Updated `Frontend/src/lib/auth.ts` line 86 to prioritize JWT permissions:
```typescript
permissions: decoded.permissions || userData.permissions || {}
```

## Test Steps

1. **Log out** from the application completely
2. **Log back in** as superadmin@codec.com
3. **Open browser console** (F12 → Console tab)
4. **Navigate to Settings page** (/settings)
5. **Check console logs** - you should see:
   - `🔍 DEBUG PermissionGuard: Full user object:` - Shows complete user data
   - `🔍 DEBUG PermissionGuard: user.permissions:` - Should show nested object like:
     ```
     {
       user: { read: true, create: true, update: true, delete: true },
       role: { read: true, create: true, update: true, delete: true },
       permission: { read: true, create: true, update: true, delete: true },
       ... (all other resources)
     }
     ```
   - `🔍 DEBUG PermissionGuard: Extracted permissions:` - Should show flat array like:
     ```
     ['user:read', 'user:create', 'user:update', 'user:delete', 'role:read', ...]
     ```

6. **Verify access granted** - Settings page should load without "Access Denied" error

## Expected Result
✅ Settings page loads successfully
✅ SuperAdmin can see all sections
✅ Console shows extracted permissions include 'user:read' and 'role:read'

## If Still Not Working
Check these additional items:
1. Verify JWT token contains permissions: Use https://jwt.io to decode the auth_token cookie
2. Check browser cookies: auth_token and user_info should both exist
3. Check backend: Verify SuperAdmin role in database has singular permission names
4. Clear browser cache/cookies and try again

## Files Modified
1. `Frontend/src/lib/auth.ts` - Fixed permission priority
2. `Frontend/src/components/auth/PermissionGuard.tsx` - Added debug logging
