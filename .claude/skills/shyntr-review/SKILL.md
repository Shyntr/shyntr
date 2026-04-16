---
name: shyntr-review
description: Use for security review, code review, refactor-risk review, and bug triage in Shyntr.
---

Review Shyntr code with a security-first lens.

Focus:
- OAuth2/OIDC, SAML, federation, multi-tenancy
- protocol correctness
- tenant isolation
- trust boundaries
- production risk

Always inspect for:
- exact redirect URI matching
- PKCE enforcement
- state and nonce handling
- client authentication
- token endpoint boundary
- callback / ACS boundary
- cross-tenant leakage
- replay opportunities
- issuer, audience, and signature validation
- unsafe logging
- SSRF or unsafe outbound requests

Primary failure rule:
1. classify the exact mismatch first:
    - implementation wrong
    - test expectation wrong
    - fixture/setup wrong
2. address the exact mismatch before secondary hardening
3. do not lead with optional improvements while the primary failure is unresolved

Incomplete-change checklist:
- handler changed but service unchanged
- service changed but store unchanged
- DTO changed but validation unchanged
- validation changed but tests still assert old behavior
- config changed but wiring/defaults unchanged
- tenant logic added in one path but not sibling paths

Scope rule:
- start from the directly failing file or boundary
- expand only if needed to classify correctly
- stop once the failure cause is confidently identified
- do not scan unrelated packages

If a snapshot exists:
- use exact snapshot paths
- do not invent missing helpers or layers

Response structure:

1. Current state
2. Confirmed findings
3. Exact mismatch classification
4. Incomplete change risks
5. Files to change
6. Full updated files or minimal remediation plan