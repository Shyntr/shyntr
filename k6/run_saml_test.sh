#!/bin/bash
set -e

ENTITY_ID="load-test-saml-sp"
TENANT_ID="default"
ADMIN_API_URL="http://localhost:7497"
BASE_URL="http://localhost:7496"

echo "[INFO] Cleaning up previous SAML state..."
curl -s -X DELETE "${ADMIN_API_URL}/admin/management/saml-clients/${TENANT_ID}/${ENTITY_ID}" > /dev/null || true
rm -f saml_request.txt generate_saml.py

echo "[INFO] Creating SAML AuthnRequest Generator..."
cat << 'EOF' > generate_saml.py
import zlib, base64, urllib.parse, time, uuid

entity_id = "load-test-saml-sp"
destination = "http://localhost:7496/t/default/saml/sso"
acs_url = "http://localhost:8080/saml/acs"
issue_instant = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
req_id = f"_{uuid.uuid4().hex}"

# 1. Standart bir SAML AuthnRequest XML'i oluşturuyoruz
xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="{req_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{destination}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{entity_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true" />
</samlp:AuthnRequest>"""

# 2. SAML standardına göre (HTTP-Redirect Binding): Deflate -> Base64 -> URL Encode
deflated = zlib.compress(xml_payload.encode('utf-8'))[2:-4]
b64 = base64.b64encode(deflated).decode('ascii')
url_encoded = urllib.parse.quote(b64)

with open("saml_request.txt", "w") as f:
    f.write(url_encoded)
EOF

python3 generate_saml.py
SAML_REQ=$(cat saml_request.txt)

echo "[INFO] Provisioning SAML SP via Admin API..."
curl -s -S -f -X POST "${ADMIN_API_URL}/admin/management/saml-clients" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "'"${ENTITY_ID}"'",
    "tenant_id": "'"${TENANT_ID}"'",
    "name": "SAML Load Test SP",
    "acs_url": "http://localhost:8080/saml/acs",
    "sign_assertion": true,
    "sign_response": true
  }' > /dev/null

echo "[INFO] Running K6 SAML Load Test..."

k6 run \
  -e BASE_URL="${BASE_URL}" \
  -e TENANT_ID="${TENANT_ID}" \
  -e SAML_REQUEST="${SAML_REQ}" \
  shyntr_saml_load_test.js

echo "[INFO] Teardown: Enforcing Cleanup..."
curl -s -S -f -X DELETE "${ADMIN_API_URL}/admin/management/saml-clients/${TENANT_ID}/${ENTITY_ID}" > /dev/null
rm -f saml_request.txt generate_saml.py
echo "[INFO] Cleanup successful."