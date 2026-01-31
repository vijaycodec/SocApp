# Test Plan: Automatic Session Expiry Handling (PATCH 54 Enhancement)

## What Was Fixed

**Issue:** When session expires or becomes invalid (401 Unauthorized), the frontend:
- ❌ Shows "Unauthorized" error
- ❌ Stays on the same page  
- ❌ Doesn't clear cache/storage
- ❌ Doesn't redirect to login

**Fix:** Automatic session cleanup and redirect on 401 response:
- ✅ Clears all cookies (auth_token, user_info, etc.)
- ✅ Clears localStorage
- ✅ Clears sessionStorage
- ✅ Clears browser cache
- ✅ Redirects to login page
- ✅ Shows clear message in console

## How It Works

**Code Location:** `/Frontend/src/lib/api.ts` (Lines 57-72)

**Logic:**
```typescript
if (response.status === 401) {
  console.log('🔒 [SESSION EXPIRED] 401 Unauthorized');
  
  // Clear all auth data (calls clearAuthSession from auth.ts)
  await clearAuthSession();
  
  // Redirect to login
  window.location.href = '/login';
  
  throw new Error('Session expired. Please login again.');
}
```

## Test Methods

### Method 1: Wait for Natural Session Expiry (Easy)

**Current Session Timeout:** 1 hour (configured in Backend/.env)

**Steps:**
1. Login to https://uat.cyberpull.space/login
2. Navigate to dashboard or any page
3. Wait 1 hour without any activity
4. Try to click any link or refresh page
5. **Expected:**
   - Console shows: `🔒 [SESSION EXPIRED] 401 Unauthorized`
   - Console shows: `🔄 [SESSION EXPIRED] Redirecting to login page...`
   - Console shows: `✅ Session cleared: all cookies, storage, and cache removed`
   - Automatically redirected to /login
   - Message: "Session expired. Please login again."

### Method 2: Manually Delete Session from Database (Fast - Recommended)

**Steps:**

1. **Login to the application:**
   - Go to https://uat.cyberpull.space/login
   - Login with your credentials
   - Navigate to dashboard

2. **Get your user ID from browser console:**
   ```javascript
   // In browser console
   JSON.parse(localStorage.getItem('auth_user')).id
   // Copy the output (e.g., "6901d95c62a2375cf33dea87")
   ```

3. **Delete your session from database (SSH to server):**
   ```bash
   mongosh soc_dashboard_uat --quiet --eval "
     db.usersessions.deleteMany({
       user_id: ObjectId('YOUR_USER_ID_HERE'),
       is_active: true
     })
   "
   # Replace YOUR_USER_ID_HERE with the ID from step 2
   ```

4. **Try to use the application:**
   - Go back to browser
   - Click any link (e.g., Overview, Alerts, Settings)
   - OR refresh the current page
   
5. **Expected Behavior:**
   - Next API request returns 401 Unauthorized
   - Browser console shows:
     ```
     🔒 [SESSION EXPIRED] 401 Unauthorized - Session expired or invalid
     🔄 [SESSION EXPIRED] Redirecting to login page...
     ✅ Session cleared: all cookies, storage, and cache removed
     ```
   - Page automatically redirects to /login
   - All storage cleared (cookies, localStorage, sessionStorage)

### Method 3: Concurrent Login Test (Tests PATCH 54)

This tests both concurrent session prevention AND automatic logout.

**Steps:**

1. **Login from Browser 1 (e.g., Chrome):**
   - Open Chrome
   - Go to https://uat.cyberpull.space/login
   - Login with credentials
   - Stay on dashboard

2. **Login from Browser 2 (e.g., Firefox):**
   - Open Firefox
   - Go to https://uat.cyberpull.space/login
   - Login with SAME credentials
   - Navigate to dashboard

3. **Go back to Browser 1 (Chrome):**
   - Click any link or refresh
   
4. **Expected in Browser 1:**
   - Backend returns 401 (session was terminated by Browser 2 login)
   - Frontend detects 401
   - Console shows session expired logs
   - Automatically redirects to /login
   - All storage cleared

5. **Expected in Browser 2:**
   - Continues working normally (active session)

## Verification Checklist

After triggering session expiry, verify:

✅ **Console Logs:**
```
🔒 [SESSION EXPIRED] 401 Unauthorized - Session expired or invalid
✅ Session cleared: all cookies, storage, and cache removed
🔄 [SESSION EXPIRED] Redirecting to login page...
```

✅ **Cookies Cleared:**
```javascript
// In browser console
Cookies.get('auth_token')  // Should return: undefined
Cookies.get('user_info')   // Should return: undefined
```

✅ **LocalStorage Cleared:**
```javascript
localStorage.getItem('token')      // Should return: null
localStorage.getItem('auth_user')  // Should return: null
Object.keys(localStorage).length   // Should return: 0
```

✅ **SessionStorage Cleared:**
```javascript
Object.keys(sessionStorage).length  // Should return: 0
```

✅ **URL Changed:**
```javascript
window.location.pathname  // Should be: "/login"
```

✅ **User Experience:**
- No error message displayed on screen (silent redirect)
- Login page loads cleanly
- Can login again successfully

## Testing Different Scenarios

### Scenario 1: Expired Session on Dashboard
```
User on dashboard → Session expires → Click "Alerts" 
→ 401 → Auto logout → Redirect to /login
```

### Scenario 2: Expired Session During Data Fetch
```
User viewing data → Session expires → Page auto-refreshes 
→ API request → 401 → Auto logout → Redirect to /login
```

### Scenario 3: Concurrent Login Forces Logout
```
Browser A logged in → Browser B logs in with same account 
→ Browser A session deleted → Browser A: next request → 401 
→ Auto logout → Redirect to /login
```

### Scenario 4: Multiple API Calls
```
User clicks button → Triggers 3 API calls simultaneously 
→ All return 401 → clearAuthSession called once (not 3 times)
→ Single redirect to /login
```

## Expected Behavior Summary

| Event | Old Behavior | New Behavior (PATCH 54) |
|-------|-------------|-------------------------|
| Session expires | Shows error, stays on page | Auto logout, clear storage, redirect to /login |
| 401 from API | Error message, manual refresh needed | Automatic cleanup and redirect |
| Concurrent login | Other browser stays logged in | Immediate logout on next request |
| Multiple 401s | Multiple errors | Single cleanup and redirect |

## Console Log Examples

**Successful Session Expiry Handling:**
```
🔒 [SESSION EXPIRED] 401 Unauthorized - Session expired or invalid
✅ Session cleared: all cookies, storage, and cache removed
🔄 [SESSION EXPIRED] Redirecting to login page...
```

**From Concurrent Login (Backend):**
```
🔍 [PATCH 54] Concurrent session config: ALLOW=false (false), MAX=1
📊 [PATCH 54] User superadmin@codec.com currently has 1 active session(s)
🔒 [PATCH 54] Single session mode: Terminating ALL 1 existing session(s)
✅ [PATCH 54] Deleted 1 session(s) from database
```

## Troubleshooting

### Issue: 401 but no redirect

**Check:**
1. Browser console for errors
2. Network tab - verify 401 response
3. Check if api.ts changes are loaded: `npm run build` completed?
4. Hard refresh (Ctrl+Shift+R) to clear browser cache

### Issue: Redirect loops

**Cause:** Login page also making API calls that return 401

**Solution:** Check that login page doesn't make authenticated API calls before login

### Issue: Storage not cleared

**Check:**
1. Browser console logs - verify clearAuthSession was called
2. Check auth.ts - ensure clearAuthSession function exists
3. Verify frontend build includes latest changes

## Quick Test Command

**To manually trigger session expiry for current user:**

```bash
# On server via SSH
mongosh soc_dashboard_uat --quiet --eval "
  print('Current active sessions:');
  db.usersessions.find({is_active: true}).forEach(s => {
    print('User: ' + s.user_id + ', IP: ' + s.ip_address);
  });
  
  // Delete all active sessions (this will force logout on next request)
  const result = db.usersessions.deleteMany({is_active: true});
  print('Deleted ' + result.deletedCount + ' session(s)');
  print('All users will be logged out on next API request');
"
```

Then go to browser and click any link - should see automatic logout and redirect.

## Success Criteria

✅ Session expiry detected (401 response)
✅ All cookies cleared
✅ All localStorage cleared
✅ All sessionStorage cleared
✅ Browser cache cleared (via clearAuthSession)
✅ Redirected to /login automatically
✅ Console shows clear logs of the process
✅ User can login again successfully
✅ No errors or infinite loops

