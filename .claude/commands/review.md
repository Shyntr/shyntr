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

PRIMARY FAILURE RULE

When the task includes failing tests, runtime mismatches, or observed errors:

1. first classify each exact mismatch:
    - implementation wrong
    - test expectation wrong
    - fixture/setup wrong
2. address the exact mismatch before proposing secondary hardening
3. do not lead with optional improvements if the primary failure is still unresolved

INCOMPLETE CHANGE DETECTION RULE

Always check whether the implementation was changed in one layer but left incomplete in another.

Look for:

- handler changed but service unchanged
- service changed but repository/store unchanged
- request DTO changed but validation unchanged
- validation changed but tests still assert old behavior
- config contract changed but defaults/wiring unchanged
- tenant-aware logic added in one path but not sibling paths
- auth flow updated at authorize time but not token or callback time

BOUNDED REVIEW RULE

Use the minimum complete affected surface only.

Do:

- inspect the directly failing file or boundary first
- expand only if needed to classify the mismatch correctly
- stop once the failure cause is confidently classified

Do not:

- scan the repository broadly
- explore adjacent packages without a concrete reason
- drift from the reported mismatch into generic hardening advice too early

Snapshot rules:

- If a snapshot exists, use only snapshot paths and visible helpers
- Never invent missing functions or layers
- Prefer minimal compatible remediation

Response structure:

1. Current state
2. Confirmed findings
3. Exact mismatch classification
4. Incomplete change risks
5. Files to change
6. Full updated files or minimal remediation plan