# Test Plan: Concurrent Session Prevention (PATCH 54)

## Current Configuration
```bash
ALLOW_CONCURRENT_SESSIONS=false  # Single session mode
MAX_CONCURRENT_SESSIONS=1
```

## Test Scenario: Login from Same IP, Different Browsers

### Pre-Test Verification
```bash
# Check current sessions (should be 0)
mongosh soc_dashboard_uat --quiet --eval "db.usersessions.countDocuments({is_active: true})"
```

### Test Steps

#### Step 1: Login from Browser 1 (e.g., Chrome)
1. Open Chrome browser
2. Go to: https://uat.cyberpull.space/login
3. Enter credentials and login
4. **Expected:** Login successful, redirected to dashboard

#### Step 2: Check Session Count
```bash
mongosh soc_dashboard_uat --quiet --eval "
  db.usersessions.find({is_active: true}, {
    user_id: 1, 
    ip_address: 1, 
    user_agent: 1, 
    createdAt: 1
  }).toArray()
"
```
**Expected:** 1 session active (from Chrome)

#### Step 3: Check Backend Logs (First Login)
```bash
pm2 logs uat-soc-backend --lines 100 | grep "PATCH 54"
```
**Expected Logs:**
```
🔍 [PATCH 54] Concurrent session config: ALLOW=false (false), MAX=1
📊 [PATCH 54] User user@example.com currently has 0 active session(s)
✅ [PATCH 54] No existing sessions to terminate
🆕 [PATCH 54] Creating new session for user user@example.com from IP X.X.X.X
✅ [PATCH 54] New session created: ID=...
📊 [PATCH 54] Login complete: User user@example.com now has 1 active session(s)
```

#### Step 4: Login from Browser 2 (e.g., Firefox) - SAME IP
1. Open Firefox browser (on same computer, same IP)
2. Go to: https://uat.cyberpull.space/login
3. Enter SAME credentials and login
4. **Expected:** Login successful, redirected to dashboard

#### Step 5: Check Backend Logs (Second Login) - KEY TEST
```bash
pm2 logs uat-soc-backend --lines 100 | grep "PATCH 54" | tail -20
```
**Expected Logs (CRITICAL):**
```
🔍 [PATCH 54] Concurrent session config: ALLOW=false (false), MAX=1
📊 [PATCH 54] User user@example.com currently has 1 active session(s)
   Session 1: ID=..., IP=X.X.X.X, Created=...
🔒 [PATCH 54] Single session mode: Terminating ALL 1 existing session(s) for user user@example.com
✅ [PATCH 54] Deleted 1 session(s) from database
✅ [PATCH 54] Verified: 0 active sessions remaining
🆕 [PATCH 54] Creating new session for user user@example.com from IP X.X.X.X
✅ [PATCH 54] New session created: ID=...
📊 [PATCH 54] Login complete: User user@example.com now has 1 active session(s)
```

#### Step 6: Verify Only ONE Session Active
```bash
mongosh soc_dashboard_uat --quiet --eval "
  db.usersessions.find({is_active: true}, {
    user_id: 1, 
    ip_address: 1, 
    user_agent: 1, 
    createdAt: 1
  }).toArray()
"
```
**Expected:** ONLY 1 session active (from Firefox - the newest login)

#### Step 7: Verify Chrome Session is TERMINATED
1. Go back to Chrome browser (Browser 1)
2. Try to navigate or refresh the dashboard
3. **Expected:** 
   - API requests return 401 Unauthorized
   - User automatically redirected to login page
   - Message: "Your session has expired"

### Success Criteria
✅ After second login, ONLY 1 session exists in database (regardless of same IP)
✅ First browser (Chrome) is automatically logged out
✅ Backend logs show: "Terminating ALL 1 existing session(s)"
✅ Backend logs show: "Deleted 1 session(s) from database"
✅ Backend logs show: "Verified: 0 active sessions remaining"
✅ Final session count: 1

### Failure Indicators
❌ Two sessions active after second login
❌ Both browsers remain logged in
❌ Backend logs show: "WARNING: Expected 1 session but found 2!"
❌ No "Terminating" message in logs

## Additional Test: Different IPs

### Test with Different IP Addresses
1. Login from IP 1 (e.g., office network)
2. Login from IP 2 (e.g., mobile hotspot or VPN)
3. **Expected:** Same behavior - first session terminated, only 1 active

## Configuration Tests

### Test 2: Allow 2 Concurrent Sessions
```bash
# Update .env
cd /home/uat.cyberpull.space/public_html/Backend
nano .env

# Change to:
ALLOW_CONCURRENT_SESSIONS=true
MAX_CONCURRENT_SESSIONS=2

# Restart
pm2 restart uat-soc-backend --update-env

# Test: Login from 3 browsers
# Expected: First 2 logins coexist, 3rd login terminates oldest
```

### Test 3: Unlimited Sessions (Not Recommended)
```bash
# Change to:
ALLOW_CONCURRENT_SESSIONS=true
MAX_CONCURRENT_SESSIONS=0

# Restart
pm2 restart uat-soc-backend --update-env

# Test: Login from multiple browsers
# Expected: All sessions remain active (no termination)
```

## Troubleshooting

### If Sessions Are Not Terminated:

1. **Check Environment Variables Loaded:**
```bash
pm2 show uat-soc-backend | grep -A 5 "env:"
# Look for ALLOW_CONCURRENT_SESSIONS
```

2. **Check Backend Logs for Config:**
```bash
pm2 logs uat-soc-backend --lines 200 | grep "Concurrent session config"
# Should show: ALLOW=false (false), MAX=1
```

3. **Check Repository Functions:**
```bash
# Verify deleteAllUserSessions function exists
grep -n "deleteAllUserSessions" /home/uat.cyberpull.space/public_html/Backend/repositories/userSessionRepository/userSession.repository.js
```

4. **Manual Database Check:**
```bash
mongosh soc_dashboard_uat --quiet --eval "
  // Count sessions before login
  const before = db.usersessions.countDocuments({is_active: true});
  print('Sessions before login: ' + before);
"
# Then login
mongosh soc_dashboard_uat --quiet --eval "
  // Count sessions after login
  const after = db.usersessions.countDocuments({is_active: true});
  print('Sessions after login: ' + after);
"
```

## Expected Behavior Summary

| Scenario | Config | Result |
|----------|--------|--------|
| Login from Chrome, then Firefox (same IP) | ALLOW=false, MAX=1 | Chrome logged out, only Firefox active |
| Login from Chrome, then Firefox (diff IP) | ALLOW=false, MAX=1 | Chrome logged out, only Firefox active |
| Login from 2 browsers | ALLOW=true, MAX=2 | Both active |
| Login from 3 browsers | ALLOW=true, MAX=2 | Oldest terminated, 2 newest active |
| Login from N browsers | ALLOW=true, MAX=0 | All active (unlimited) |

