#!/bin/bash

echo "========================================"
echo "PATCH 61: Rate Limiting Test"
echo "Testing that different users have separate rate limits"
echo "========================================"
echo ""

# Test User 1: Try to login 6 times (should hit rate limit on 6th attempt)
echo "Test 1: User 'testuser1' - 6 login attempts (should block on 6th)"
echo "---------------------------------------------------------------"

for i in {1..6}; do
  echo -n "Attempt $i: "
  response=$(curl -s -X POST http://localhost:5555/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"identifier":"testuser1","password":"WrongPass123!","recaptchaToken":"test"}')
  
  if echo "$response" | grep -q "Too many login attempts"; then
    echo "RATE LIMITED ✓"
  else
    echo "$(echo $response | jq -r '.message')"
  fi
  sleep 1
done

echo ""
echo "Test 2: User 'testuser2' - Should NOT be blocked (different user)"
echo "---------------------------------------------------------------"

# Test User 2: Should be able to login even though User 1 is rate limited
response=$(curl -s -X POST http://localhost:5555/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"testuser2","password":"WrongPass123!","recaptchaToken":"test"}')

if echo "$response" | grep -q "Too many login attempts"; then
  echo "FAILED: testuser2 is blocked (bug not fixed) ✗"
else
  echo "SUCCESS: testuser2 can still attempt login ✓"
  echo "Response: $(echo $response | jq -r '.message')"
fi

echo ""
echo "Test 3: User 'testuser3' - Should also NOT be blocked"
echo "---------------------------------------------------------------"

response=$(curl -s -X POST http://localhost:5555/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"testuser3","password":"WrongPass123!","recaptchaToken":"test"}')

if echo "$response" | grep -q "Too many login attempts"; then
  echo "FAILED: testuser3 is blocked (bug not fixed) ✗"
else
  echo "SUCCESS: testuser3 can still attempt login ✓"
  echo "Response: $(echo $response | jq -r '.message')"
fi

echo ""
echo "========================================"
echo "Test Complete"
echo "========================================"
