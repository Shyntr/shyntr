#!/bin/bash
set -e

CLIENT_ID="pki-load-test-client"
TENANT_ID="default"
ADMIN_API_URL="http://localhost:7497"

echo "[INFO] Cleaning up any previous state..."
curl -s -X DELETE "${ADMIN_API_URL}/admin/management/clients/${TENANT_ID}/${CLIENT_ID}" > /dev/null || true
rm -f loadtest_private.pem loadtest_public.pem assertions.json generate_assertions.py jwk.json

echo "[INFO] Generating ephemeral RSA 2048 Key Pair for testing..."
openssl genpkey -algorithm RSA -out loadtest_private.pem -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl rsa -pubout -in loadtest_private.pem -out loadtest_public.pem 2>/dev/null

echo "[INFO] Converting Public Key to JWK and Pre-computing JWT Assertions..."
cat << 'EOF' > generate_assertions.py
import sys, json, base64, time, uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def to_b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

# 1. Generate JWK
with open('loadtest_public.pem', 'rb') as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
numbers = pub_key.public_numbers()
jwk = {
    'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'kid': 'loadtest-key-1',
    'n': to_b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')),
    'e': to_b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big'))
}
with open('jwk.json', 'w') as f:
    json.dump({'keys': [jwk]}, f)

# 2. Generate Pre-computed JWT Assertions (1,000,000 adet)
with open('loadtest_private.pem', 'rb') as f:
    priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

header = to_b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode('utf-8'))
client_id = "pki-load-test-client"
token_endpoint = "http://localhost:7496/t/default/oauth2/token"
current_time = int(time.time())

assertions = []
print("Generating 1,000,000 unique client assertions... (Takes ~4 mins)")
for i in range(1000000):
    payload_dict = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "exp": current_time + 3600,
        "nbf": current_time - 5,
        "iat": current_time,
        "jti": str(uuid.uuid4())
    }
    payload = to_b64url(json.dumps(payload_dict).encode('utf-8'))
    msg = f"{header}.{payload}".encode('ascii')
    sig = priv_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    assertions.append(f"{header}.{payload}.{to_b64url(sig)}")

with open('assertions.json', 'w') as f:
    json.dump(assertions, f)
EOF

python3 generate_assertions.py
JWK_JSON=$(cat jwk.json)

echo "[INFO] Provisioning PKI Client via Admin API..."
curl -s -S -f -X POST "${ADMIN_API_URL}/admin/management/clients" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "'"${CLIENT_ID}"'",
    "tenant_id": "'"${TENANT_ID}"'",
    "name": "PKI Load Test Client",
    "redirect_uris": ["http://localhost:8080/callback"],
    "scopes": ["openid"],
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": '"${JWK_JSON}"'
  }' > /dev/null

echo "[INFO] Client and JWKS successfully created. Running K6 Load Test..."

k6 run \
  -e BASE_URL="http://localhost:7496" \
  -e TENANT_ID="${TENANT_ID}" \
  shyntr_pki_load_test.js

echo "[INFO] Load Test Complete. Enforcing Least Privilege Cleanup..."
curl -s -S -f -X DELETE "${ADMIN_API_URL}/admin/management/clients/${TENANT_ID}/${CLIENT_ID}" > /dev/null
rm -f loadtest_private.pem loadtest_public.pem assertions.json jwk.json generate_assertions.py

echo "[INFO] Teardown successful. All temporary cryptographic material destroyed."