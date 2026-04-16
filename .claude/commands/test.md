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

PRIMARY FAILURE RULE

When a test is failing or a runtime mismatch is provided:

1. first classify the exact mismatch:
    - implementation wrong
    - test expectation wrong
    - fixture/setup wrong
2. fix the exact mismatch first
3. only after that, add secondary hardening assertions if they are still useful
4. do not replace root-cause analysis with general test strengthening

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

For every behavior change, add only the tests needed to prove the entire affected surface is correct.

Choose the minimum sufficient set:

- unit/security test for local invariant
- integration test for endpoint or boundary behavior
- regression test for production bug reproduction

Prefer:

- one strong integration test over many shallow tests
- one regression test per real bug
- boundary-focused assertions over internal implementation assertions

BOUNDED TEST SCOPE RULE

Start from the failing test or requested boundary.

Do:

- inspect the failing test first
- inspect only the directly related handler/setup path if needed
- reuse existing helpers before creating anything new
- stop once the failing behavior is correctly covered

Do not:

- scan unrelated packages
- create generic helpers unless clearly needed by multiple tests
- add broad suites to fix a narrow failure
- change product behavior just to satisfy a wrong test

Output structure:

1. Current state
2. Problem / risk
3. Files to change
4. Full updated files
5. Targeted validation