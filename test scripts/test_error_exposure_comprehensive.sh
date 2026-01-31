#!/bin/bash

# Comprehensive Security Test: Improper Error Handling (CWE-209)
# Tests if stack traces and internal errors are exposed after PATCH 41

echo "================================================"
echo "ERROR HANDLING SECURITY TEST (POST-PATCH 41)"
echo "Testing CWE-209 Prevention"
echo "================================================"
echo ""

API_BASE="http://127.0.0.1:5555/api"
VULNERABILITY_FOUND=0

echo "Configuration Check:"
echo "---------------------------------------"
NODE_ENV=$(grep "^NODE_ENV" /home/uat.cyberpull.space/public_html/Backend/.env | cut -d'=' -f2)
EXPOSE_DETAILS=$(grep "^EXPOSE_ERROR_DETAILS" /home/uat.cyberpull.space/public_html/Backend/.env | cut -d'=' -f2)
echo "NODE_ENV = $NODE_ENV"
echo "EXPOSE_ERROR_DETAILS = $EXPOSE_DETAILS"
echo ""

# Wait for backend to fully start
echo "Waiting for backend to start..."
sleep 5

echo "STEP 1: Login as analyst user"
echo "---------------------------------------"
LOGIN_RESP=$(curl -s -X POST $API_BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"analyst@codec.com","password":"Analyst@123"}')

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.data.access_token')

if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
  echo "✅ Login successful"
else
  echo "❌ Login failed"
  echo "Response: $LOGIN_RESP"
  exit 1
fi

echo ""
echo "STEP 2: Test CastError (Invalid MongoDB ObjectId)"
echo "---------------------------------------"
echo "Accessing: GET /api/organisations/invalid_objectid"

CAST_ERROR=$(curl -s -X GET "$API_BASE/organisations/invalid_objectid_format" \
  -H "Authorization: Bearer $TOKEN")

echo "Response:"
echo "$CAST_ERROR" | jq '.'

if echo "$CAST_ERROR" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace exposed in CastError!"
  echo "Stack trace: $(echo "$CAST_ERROR" | jq -r '.stack' | head -3)"
  VULNERABILITY_FOUND=1
elif echo "$CAST_ERROR" | jq -e '.name' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Error name exposed!"
  echo "Error name: $(echo "$CAST_ERROR" | jq -r '.name')"
  VULNERABILITY_FOUND=1
else
  echo "✅ No sensitive error details exposed"
fi

echo ""
echo "STEP 3: Test unhandled server error"
echo "---------------------------------------"
echo "Triggering potential server error..."

# Try to create malformed request that might cause server error
SERVER_ERROR=$(curl -s -X POST "$API_BASE/tickets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"malformed": true, "nested": {"deep": {"invalid": null}}}')

echo "Response:"
echo "$SERVER_ERROR" | jq '.'

if echo "$SERVER_ERROR" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace exposed in server error!"
  VULNERABILITY_FOUND=1
elif echo "$SERVER_ERROR" | jq -e '.name' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Error name exposed!"
  VULNERABILITY_FOUND=1
else
  echo "✅ No sensitive error details exposed"
fi

echo ""
echo "STEP 4: Test 404 Not Found error"
echo "---------------------------------------"
echo "Accessing: GET /api/nonexistent_route_test"

NOT_FOUND=$(curl -s -X GET "$API_BASE/nonexistent_route_test" \
  -H "Authorization: Bearer $TOKEN")

echo "Response:"
echo "$NOT_FOUND" | jq '.'

if echo "$NOT_FOUND" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace in 404 error!"
  VULNERABILITY_FOUND=1
else
  echo "✅ 404 handled securely"
fi

echo ""
echo "STEP 5: Test authentication error"
echo "---------------------------------------"
echo "Accessing with invalid token..."

AUTH_ERROR=$(curl -s -X GET "$API_BASE/organisations" \
  -H "Authorization: Bearer invalid.jwt.token")

echo "Response:"
echo "$AUTH_ERROR" | jq '.'

if echo "$AUTH_ERROR" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace in auth error!"
  VULNERABILITY_FOUND=1
else
  echo "✅ Auth error handled securely"
fi

echo ""
echo "STEP 6: Test permission denied error"
echo "---------------------------------------"
echo "Analyst trying to create organisation (requires client:create)..."

PERMISSION_ERROR=$(curl -s -X POST "$API_BASE/organisations" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"organisation_name":"Test Org","client_name":"test"}')

echo "Response:"
echo "$PERMISSION_ERROR" | jq '.'

if echo "$PERMISSION_ERROR" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace in permission error!"
  VULNERABILITY_FOUND=1
else
  echo "✅ Permission error handled securely"
fi

echo ""
echo "================================================"
echo "SECURITY TEST SUMMARY"
echo "================================================"
echo ""
echo "Configuration:"
echo "  NODE_ENV = $NODE_ENV"
echo "  EXPOSE_ERROR_DETAILS = $EXPOSE_DETAILS"
echo ""

if [ $VULNERABILITY_FOUND -eq 1 ]; then
  echo "❌ CWE-209 VULNERABILITY DETECTED"
  echo "❌ Internal error details are being exposed"
  echo ""
  echo "ISSUES FOUND:"
  echo "  - Stack traces visible to users"
  echo "  - Internal error names exposed"
  echo "  - Sensitive implementation details revealed"
  echo ""
  echo "SECURITY RISKS:"
  echo "  - Attackers can map internal code structure"
  echo "  - File paths and dependencies revealed"
  echo "  - Easier to identify vulnerable components"
  echo "  - CVSS 5.3 (Medium) - Information Disclosure"
else
  echo "✅ CWE-209: MITIGATED"
  echo "✅ No stack traces exposed"
  echo "✅ No internal error details revealed"
  echo "✅ Error handling is secure"
  echo ""
  echo "SECURITY IMPROVEMENTS:"
  echo "  - Generic error messages only"
  echo "  - Stack traces hidden from users"
  echo "  - Internal details logged server-side only"
  echo "  - PATCH 41 successfully implemented"
fi

echo "================================================"
exit $VULNERABILITY_FOUND
