Use this command for designing, reviewing, or implementing Shyntr tests.

Mission:
Build deterministic, security-first, repository-local tests for Shyntr that validate:

- OIDC / OAuth2 protocol correctness
- SAML protocol correctness
- tenant isolation
- protocol bridging behavior
- PKCE enforcement
- logout/session safety
- regression safety across releases

Core principles:

- Secure by default
- Enforce strict tenant isolation
- Prefer deterministic tests over broad but flaky coverage
- Never introduce runtime dependency on external conformance platforms
- Never invent repository structure when a snapshot exists
- Never change expected behavior to satisfy a test unless the behavior is actually wrong
- Treat the token endpoint as a trust boundary
- Treat tenant-scoped routing as a security boundary
- Do not log secrets, tokens, raw assertions, private keys, or credentials in tests

Test strategy order:

1. Discovery / metadata contract tests
2. Authorization endpoint boundary tests
3. Token endpoint boundary tests
4. UserInfo contract tests
5. Logout / session safety tests
6. Tenant isolation tests
7. Bridge tests
8. Regression tests for closed bugs

Layering:

- Use fast unit/security tests for validators, claim mapping, replay protection, issuer/audience/signature checks,
  tenant guards, logout token checks
- Prefer integration tests for real HTTP handler behavior with in-repo test DB setup
- Use E2E only when the flow truly requires multiple components

CHANGE COVERAGE RULE
For every behavior change, add the smallest test set that proves the full affected surface is consistent.

At minimum, decide whether the change needs:

- unit/security test
- handler/integration test
- regression test

Prefer:

- one strong integration test over many shallow unit tests
- one regression test per real bug
- endpoint-level assertions when behavior crosses boundaries

Output structure:

1. Current state
2. Problem / risk
3. Files to change
4. Full updated files