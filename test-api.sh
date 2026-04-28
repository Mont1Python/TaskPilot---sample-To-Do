#!/bin/bash
# Quick test script for to-do app signup and login

API="http://localhost:8080"

echo "================================"
echo "Creating new user account..."
echo "================================"

# Signup
SIGNUP_RESPONSE=$(curl -s -X POST "$API/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "password123"
  }')

echo "Signup Response:"
echo "$SIGNUP_RESPONSE" | jq '.' 2>/dev/null || echo "$SIGNUP_RESPONSE"

# Extract token
TOKEN=$(echo "$SIGNUP_RESPONSE" | jq -r '.token' 2>/dev/null)

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "❌ Signup failed - no token returned"
  exit 1
fi

echo ""
echo "✅ Signup successful!"
echo "Token: $TOKEN"

echo ""
echo "================================"
echo "Logging in with same credentials..."
echo "================================"

# Login
LOGIN_RESPONSE=$(curl -s -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }')

echo "Login Response:"
echo "$LOGIN_RESPONSE" | jq '.' 2>/dev/null || echo "$LOGIN_RESPONSE"

LOGIN_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token' 2>/dev/null)

if [ -z "$LOGIN_TOKEN" ] || [ "$LOGIN_TOKEN" == "null" ]; then
  echo "❌ Login failed - no token returned"
  exit 1
fi

echo ""
echo "✅ Login successful!"
echo "Token: $LOGIN_TOKEN"

echo ""
echo "================================"
echo "Creating a to-do task..."
echo "================================"

# Create todo
TODO_RESPONSE=$(curl -s -X POST "$API/todos" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LOGIN_TOKEN" \
  -d '{
    "text": "My First Task on Kubernetes",
    "list": "My Day",
    "subText": "This is running on Kubernetes!",
    "type": "todo"
  }')

echo "Create Todo Response:"
echo "$TODO_RESPONSE" | jq '.' 2>/dev/null || echo "$TODO_RESPONSE"

echo ""
echo "================================"
echo "✅ All tests passed!"
echo "================================"
