#!/bin/bash

# Security Test: Session Hijacking Prevention (CWE-384)
# This test replicates the vulnerability report scenario

echo "================================================"
echo "SESSION HIJACKING SECURITY TEST"
echo "Testing CWE-384 Protection"
echo "================================================"
echo ""

API_BASE="http://127.0.0.1:5555/api"

echo "STEP 1: Login and capture session token/cookie"
echo "---------------------------------------"
LOGIN_RESP=$(curl -s -X POST $API_BASE/auth/login \
  -H "Content-Type: application/json" \
  -c /tmp/cookies.txt \
  -D /tmp/response_headers.txt \
  -d '{"identifier":"superadmin@codec.com","password":"SuperStrong@123"}')

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.data.access_token')

if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
  echo "✅ Login successful - Token captured"
  echo "   Token (first 50 chars): ${TOKEN:0:50}..."
  echo "$TOKEN" > /tmp/hijack_token.txt

  # Extract session_id
  SESSION_PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null)
  SESSION_ID=$(echo "$SESSION_PAYLOAD" | jq -r '.session_id')
  echo "   Session ID: $SESSION_ID"
else
  echo "❌ Login failed"
  exit 1
fi

echo ""
echo "Checking for cookies in response:"
if [ -f /tmp/cookies.txt ] && [ -s /tmp/cookies.txt ]; then
  echo "✅ Cookies found:"
  cat /tmp/cookies.txt | grep -v "^#"
else
  echo "ℹ️  No cookies set (application uses JWT in Authorization header)"
fi

echo ""
echo "STEP 2: Verify token works BEFORE logout"
echo "---------------------------------------"
BEFORE_LOGOUT=$(curl -s -X GET $API_BASE/organisations \
  -H "Authorization: Bearer $TOKEN")

if echo "$BEFORE_LOGOUT" | grep -q '"success":true'; then
  echo "✅ Token works before logout"
  ORG_COUNT=$(echo "$BEFORE_LOGOUT" | jq '.data | length')
  echo "   Retrieved $ORG_COUNT organisations"
else
  echo "❌ Token doesn't work before logout"
  echo "   Response: $BEFORE_LOGOUT"
fi

echo ""
echo "STEP 3: Logout from account"
echo "---------------------------------------"
LOGOUT_RESP=$(curl -s -X POST $API_BASE/auth/logout \
  -H "Authorization: Bearer $TOKEN")

echo "Logout response: $(echo "$LOGOUT_RESP" | jq -c '.')"

if echo "$LOGOUT_RESP" | grep -q '"success":true'; then
  echo "✅ Logout successful"

  # Check session status in database
  SESSION_STATUS=$(mongosh soc_dashboard_uat --quiet --eval "
    var s = db.usersessions.findOne({_id: ObjectId('$SESSION_ID')});
    if (s) {
      print('Session is_active: ' + s.is_active);
      print('Termination reason: ' + s.termination_reason);
    } else {
      print('Session not found in database');
    }
  ")
  echo "   Database status:"
  echo "$SESSION_STATUS" | sed 's/^/     /'
else
  echo "❌ Logout failed"
fi

echo ""
echo "STEP 4: Attempt session hijacking (reuse captured token)"
echo "---------------------------------------"
echo "Simulating attacker using captured token after logout..."

HIJACK_ATTEMPT=$(curl -s -X GET $API_BASE/organisations \
  -H "Authorization: Bearer $TOKEN")

echo ""
if echo "$HIJACK_ATTEMPT" | grep -q '"success":true'; then
  echo "❌ VULNERABILITY CONFIRMED: Session hijacking possible!"
  echo "❌ Token still works after logout - Session not invalidated"
  echo "   Response: $(echo "$HIJACK_ATTEMPT" | jq -c '{success, message}')"
  EXIT_CODE=1
elif echo "$HIJACK_ATTEMPT" | grep -q "Session has expired or been revoked"; then
  echo "✅ SECURITY FIX CONFIRMED: Session hijacking prevented!"
  echo "✅ Token rejected after logout - Session properly invalidated"
  echo "   Message: $(echo "$HIJACK_ATTEMPT" | jq -r '.message')"
  EXIT_CODE=0
else
  echo "⚠️  Unexpected response:"
  echo "   $(echo "$HIJACK_ATTEMPT" | jq -c '.')"
  EXIT_CODE=2
fi

echo ""
echo "STEP 5: Verify session cannot be used with cookies either"
echo "---------------------------------------"
if [ -f /tmp/cookies.txt ] && [ -s /tmp/cookies.txt ]; then
  echo "Testing with captured cookies..."
  COOKIE_ATTEMPT=$(curl -s -X GET $API_BASE/organisations \
    -b /tmp/cookies.txt)

  if echo "$COOKIE_ATTEMPT" | grep -q '"success":true'; then
    echo "❌ VULNERABILITY: Session accessible via cookies after logout!"
    EXIT_CODE=1
  else
    echo "✅ Cookies also invalidated/not used for authentication"
  fi
else
  echo "ℹ️  No cookies to test (application uses JWT only)"
fi

echo ""
echo "================================================"
echo "SECURITY TEST SUMMARY"
echo "================================================"

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ Session hijacking prevention: WORKING"
  echo "✅ Logout invalidates session: CONFIRMED"
  echo "✅ Token reuse after logout: BLOCKED"
  echo "✅ CWE-384 (Session Hijacking): MITIGATED"
else
  echo "❌ Session hijacking prevention: FAILED"
  echo "❌ Logout does not invalidate session"
  echo "❌ Token can be reused after logout"
  echo "❌ CWE-384 (Session Hijacking): VULNERABLE"
fi

echo "================================================"
exit $EXIT_CODE
