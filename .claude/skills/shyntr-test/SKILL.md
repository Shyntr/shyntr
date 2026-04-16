---
name: shyntr-test
description: Use for designing, reviewing, and implementing deterministic Shyntr tests.
---

Design, review, or implement Shyntr tests.

Mission:
Build deterministic, security-first, repository-local tests for:

- OIDC / OAuth2 correctness
- SAML correctness
- tenant isolation
- protocol bridging
- PKCE enforcement
- logout/session safety
- regression safety

Core principles:

- secure by default
- strict tenant isolation
- deterministic over flaky
- no external runtime dependency on conformance platforms
- never invent repository structure when a snapshot exists
- do not change expected behavior just to satisfy a test unless the behavior is actually wrong

Primary failure rule:

1. classify the exact mismatch first:
    - implementation wrong
    - test expectation wrong
    - fixture/setup wrong
2. fix the real mismatch first
3. only then add secondary hardening assertions

Prefer:

- integration tests for auth flow behavior
- real HTTP boundaries when behavior depends on redirects, cookies, headers, or endpoint semantics
- one strong integration test over many shallow tests
- one regression test per real bug

Coverage priorities:

1. discovery / metadata
2. authorization endpoint
3. token endpoint
4. userinfo
5. logout / session safety
6. tenant isolation
7. bridge flows
8. regression tests

Bounded scope rule:

- start from the failing test or requested boundary
- inspect only directly related handler/setup code if needed
- reuse existing helpers before creating new ones
- stop once the failing behavior is correctly covered
- do not scan unrelated packages

If a snapshot exists:

- use exact package names, helpers, constructors, and paths from the snapshot

Output:

1. Current state
2. Problem / risk
3. Files to change
4. Full updated files
5. Targeted validation