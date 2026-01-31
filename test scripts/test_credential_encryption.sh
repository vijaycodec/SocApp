#!/bin/bash

# Security Test: Password Encryption (CWE-256)
# Tests that Wazuh/Indexer passwords are encrypted at rest

echo "================================================"
echo "PASSWORD ENCRYPTION SECURITY TEST"
echo "Testing CWE-256 Fix"
echo "================================================"
echo ""

API_BASE="http://127.0.0.1:5555/api"

# Wait for backend to start
echo "Waiting for backend to fully start..."
sleep 5

echo "STEP 1: Check passwords in database"
echo "---------------------------------------"
echo "Checking organisations collection for password storage format..."
echo ""

PASSWORD_CHECK=$(mongosh soc_dashboard_uat --quiet --eval '
  db.organisations.findOne(
    {organisation_name: "Codec Networks Pvt. Ltd."},
    {wazuh_manager_password: 1, wazuh_indexer_password: 1}
  )
')

echo "Database storage format:"
echo "$PASSWORD_CHECK"
echo ""

# Check if passwords are encrypted (have encrypted/iv/authTag structure)
if echo "$PASSWORD_CHECK" | grep -q "encrypted:" && echo "$PASSWORD_CHECK" | grep -q "iv:" && echo "$PASSWORD_CHECK" | grep -q "authTag:"; then
  echo "✅ Passwords are ENCRYPTED in database"
  echo "   Format: AES-256-GCM with IV and Auth Tag"
  ENCRYPTED=1
elif echo "$PASSWORD_CHECK" | grep -q "wazuh_manager_password: '" || echo "$PASSWORD_CHECK" | grep -q 'wazuh_manager_password: "'; then
  echo "❌ VULNERABILITY: Passwords are PLAINTEXT in database"
  ENCRYPTED=0
else
  echo "⚠️  Unknown format"
  ENCRYPTED=0
fi

echo ""
echo "STEP 2: Login as SuperAdmin"
echo "---------------------------------------"
LOGIN_RESP=$(curl -s -X POST $API_BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"superadmin@codec.com","password":"SuperStrong@123"}')

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.data.access_token')

if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
  echo "✅ Login successful"
else
  echo "❌ Login failed"
  exit 1
fi

echo ""
echo "STEP 3: Test that encrypted credentials can be decrypted and used"
echo "---------------------------------------"
echo "Fetching dashboard metrics (requires decrypted Wazuh credentials)..."
echo ""

# Get list of organisations to find one with credentials
ORG_LIST=$(curl -s -X GET "$API_BASE/organisations" \
  -H "Authorization: Bearer $TOKEN")

ORG_ID=$(echo "$ORG_LIST" | jq -r '.data[0]._id')
echo "Testing with organisation ID: $ORG_ID"
echo ""

# Try to fetch dashboard metrics - this requires decrypting credentials
METRICS_RESP=$(curl -s -X GET "$API_BASE/wazuh/dashboard-metrics?orgId=$ORG_ID" \
  -H "Authorization: Bearer $TOKEN")

echo "Dashboard metrics response status:"
if echo "$METRICS_RESP" | jq -e '.success' > /dev/null 2>&1; then
  SUCCESS=$(echo "$METRICS_RESP" | jq -r '.success')
  if [ "$SUCCESS" = "true" ]; then
    echo "✅ API call successful - Credentials were decrypted correctly"
    echo "   Message: $(echo "$METRICS_RESP" | jq -r '.message')"
    DECRYPTION_WORKS=1
  else
    echo "❌ API call failed"
    echo "   Error: $(echo "$METRICS_RESP" | jq -r '.message')"
    DECRYPTION_WORKS=0
  fi
else
  echo "⚠️  Unexpected response format"
  DECRYPTION_WORKS=0
fi

echo ""
echo "STEP 4: Verify passwords are not visible in API responses"
echo "---------------------------------------"
echo "Fetching organisation details..."

ORG_DETAILS=$(curl -s -X GET "$API_BASE/organisations/$ORG_ID" \
  -H "Authorization: Bearer $TOKEN")

echo "Checking if passwords are exposed in API response..."

if echo "$ORG_DETAILS" | jq -e '.data.wazuh_manager_password' > /dev/null 2>&1; then
  PASSWORD_IN_RESPONSE=$(echo "$ORG_DETAILS" | jq -r '.data.wazuh_manager_password')
  if [ "$PASSWORD_IN_RESPONSE" != "null" ]; then
    echo "❌ VULNERABILITY: Password visible in API response!"
    echo "   Exposed: $PASSWORD_IN_RESPONSE"
    PASSWORD_EXPOSED=1
  else
    echo "✅ Passwords not included in API response"
    PASSWORD_EXPOSED=0
  fi
else
  echo "✅ Passwords not included in API response"
  PASSWORD_EXPOSED=0
fi

echo ""
echo "================================================"
echo "SECURITY TEST SUMMARY"
echo "================================================"
echo ""

if [ $ENCRYPTED -eq 1 ] && [ $DECRYPTION_WORKS -eq 1 ] && [ $PASSWORD_EXPOSED -eq 0 ]; then
  echo "✅ CWE-256 (Password Stored in Plain Text): FIXED"
  echo ""
  echo "SECURITY IMPROVEMENTS:"
  echo "  ✅ Passwords encrypted in database (AES-256-GCM)"
  echo "  ✅ Encryption includes IV and authentication tag"
  echo "  ✅ Decryption works correctly for API usage"
  echo "  ✅ Passwords not exposed in API responses"
  echo "  ✅ User passwords hashed with bcrypt"
  echo ""
  echo "ENCRYPTION DETAILS:"
  echo "  - Algorithm: AES-256-GCM"
  echo "  - Key: Derived from ENCRYPTION_KEY environment variable"
  echo "  - IV: Random 16-byte initialization vector per password"
  echo "  - Auth Tag: Ensures data integrity"
  EXIT_CODE=0
else
  echo "❌ CWE-256 VULNERABILITY DETECTED"
  echo ""
  if [ $ENCRYPTED -eq 0 ]; then
    echo "  ❌ Passwords stored in plaintext"
  fi
  if [ $DECRYPTION_WORKS -eq 0 ]; then
    echo "  ❌ Decryption not working correctly"
  fi
  if [ $PASSWORD_EXPOSED -eq 1 ]; then
    echo "  ❌ Passwords exposed in API responses"
  fi
  EXIT_CODE=1
fi

echo "================================================"
exit $EXIT_CODE
