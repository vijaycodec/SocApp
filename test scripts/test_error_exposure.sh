#!/bin/bash

# Security Test: Improper Error Handling (CWE-209)
# Tests if stack traces and internal errors are exposed

echo "================================================"
echo "ERROR HANDLING SECURITY TEST"
echo "Testing CWE-209 (Improper Error Handling)"
echo "================================================"
echo ""

API_BASE="http://127.0.0.1:5555/api"

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
echo "STEP 2: Trigger CastError with invalid ObjectId"
echo "---------------------------------------"
CAST_ERROR=$(curl -s -X GET "$API_BASE/organisations/invalid_objectid_12345" \
  -H "Authorization: Bearer $TOKEN")

echo "Response:"
echo "$CAST_ERROR" | jq '.'

if echo "$CAST_ERROR" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace exposed!"
  echo ""
  echo "Stack trace found in response:"
  echo "$CAST_ERROR" | jq -r '.stack' | head -10
  VULNERABILITY=1
else
  echo "✅ No stack trace exposed"
  VULNERABILITY=0
fi

echo ""
echo "STEP 3: Trigger validation error with malformed data"
echo "---------------------------------------"
VALIDATION_ERROR=$(curl -s -X POST "$API_BASE/organisations" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"invalid_field": "test"}')

echo "Response:"
echo "$VALIDATION_ERROR" | jq '.'

if echo "$VALIDATION_ERROR" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace exposed in validation error!"
  VULNERABILITY=1
elif echo "$VALIDATION_ERROR" | jq -e '.name' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Internal error name exposed!"
  VULNERABILITY=1
else
  echo "✅ No internal error details exposed"
fi

echo ""
echo "STEP 4: Check NODE_ENV configuration"
echo "---------------------------------------"
NODE_ENV=$(grep "^NODE_ENV" /home/uat.cyberpull.space/public_html/Backend/.env | cut -d'=' -f2)
echo "NODE_ENV = $NODE_ENV"

if [ "$NODE_ENV" = "development" ]; then
  echo "⚠️  WARNING: Backend is running in DEVELOPMENT mode"
  echo "   This exposes stack traces and internal error details"
  echo "   Security risk: CWE-209 (Information Exposure Through Error Messages)"
fi

echo ""
echo "STEP 5: Test unhandled route error"
echo "---------------------------------------"
NOT_FOUND=$(curl -s -X GET "$API_BASE/nonexistent_endpoint_12345" \
  -H "Authorization: Bearer $TOKEN")

echo "Response:"
echo "$NOT_FOUND" | jq '.'

if echo "$NOT_FOUND" | jq -e '.stack' > /dev/null 2>&1; then
  echo "❌ VULNERABILITY: Stack trace exposed for 404 errors!"
  VULNERABILITY=1
else
  echo "✅ 404 error handled gracefully"
fi

echo ""
echo "================================================"
echo "SECURITY TEST SUMMARY"
echo "================================================"

if [ $VULNERABILITY -eq 1 ]; then
  echo "❌ CWE-209 VULNERABILITY CONFIRMED"
  echo "❌ Stack traces and internal errors are exposed"
  echo "❌ NODE_ENV=development reveals sensitive information"
  echo ""
  echo "RISK: Attackers can:"
  echo "  - View stack traces to understand code structure"
  echo "  - See file paths and internal architecture"
  echo "  - Identify vulnerable libraries and versions"
  echo "  - Plan targeted attacks based on exposed information"
else
  echo "✅ Error handling is secure"
  echo "✅ No stack traces or internal details exposed"
  echo "✅ CWE-209: MITIGATED"
fi

echo "================================================"
exit $VULNERABILITY
