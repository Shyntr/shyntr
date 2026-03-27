#!/bin/bash
set -e

echo "[INFO] Provisioning Load Test Client via Admin API..."

CLIENT_ID="load-test-client"
CLIENT_SECRET="load-test-secret"
TENANT_ID="default"
ADMIN_API_URL="http://localhost:7497" # Admin API Port

curl -s -S -f -X POST "${ADMIN_API_URL}/admin/management/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "'"${CLIENT_ID}"'",
    "tenant_id": "'"${TENANT_ID}"'",
    "name": "K6 Load Test Client",
    "client_secret": "'"${CLIENT_SECRET}"'",
    "scopes": ["openid"],
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_basic"
  }' > /dev/null

echo "[INFO] Client created successfully."

echo "[INFO] Running K6 Load Test..."

k6 run \
  -e BASE_URL="http://localhost:7496" \
  -e CLIENT_ID="${CLIENT_ID}" \
  -e CLIENT_SECRET="${CLIENT_SECRET}" \
  -e TENANT_ID="${TENANT_ID}" \
  shyntr_load_test.js

echo "[INFO] Load Test Complete. Cleaning up..."

curl -s -S -f -X DELETE "${ADMIN_API_URL}/admin/management/clients/${TENANT_ID}/${CLIENT_ID}" > /dev/null

echo "[INFO] Cleanup successful."