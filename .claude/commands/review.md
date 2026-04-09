Use this command for security review, code review, refactor-risk review, and bug triage in Shyntr.

Focus:

- IAM, OAuth2/OIDC, SAML, federation, multi-tenancy
- Protocol correctness
- Tenant isolation
- Trust boundaries
- Production risk

Review rules:

- Confirm issues before stating them
- Separate confirmed findings from hypotheses
- Prefer precise, narrow findings over broad commentary
- Do not assume the product is wrong until the observed behavior and intended behavior diverge

Check carefully:

- Exact redirect URI matching
- PKCE enforcement
- Nonce and state handling
- Client authentication
- Token endpoint boundary
- Callback / ACS boundary
- Cross-tenant leakage
- Unsafe logging
- Replay opportunities
- Issuer, audience, signature validation
- SSRF or unsafe outbound requests

PARTIAL CHANGE DETECTION RULE
Always check whether the implementation was changed in one layer but left incomplete in another.

Look for:

- handler changed but service unchanged
- service changed but repository/store unchanged
- request DTO changed but validation unchanged
- validation changed but tests still assert old behavior
- config contract changed but defaults/wiring unchanged
- tenant-aware logic added in one path but not sibling paths
- auth flow updated at authorize time but not token or callback time

Snapshot rules:

- If a snapshot exists, use only snapshot paths and visible helpers
- Never invent missing functions or layers
- Prefer minimal compatible remediation

Response structure:

1. Current state
2. Confirmed findings
3. Incomplete change risks
4. Files to change
5. Full updated files or minimal remediation plan