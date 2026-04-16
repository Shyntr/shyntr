# Shyntr Test Architecture Progress Report and Execution Guide

## Purpose

This document captures the current testing state of Shyntr, the architectural decisions behind the test model, the implemented E2E trust-boundary coverage, and the operating rules for future test work.

It is intended to be the working reference for:
- protocol correctness validation
- tenant isolation validation
- federation and bridge validation
- regression policy
- CI lane execution
- future test expansion

---

## 1. Core Testing Principles

Shyntr testing follows these rules:

- secure by default
- strict tenant isolation in every flow
- deterministic and repository-local where practical
- trust-boundary testing over shallow happy-path-only testing
- every confirmed production bug must add regression coverage
- no external test service dependency for correctness
- production behavior must not be changed just to satisfy a test unless the behavior is actually wrong

### Security invariants that matter most

- exact redirect URI matching
- PKCE enforcement
- tenant-scoped routing and client isolation
- state / nonce / RelayState continuity
- logout redirect safety
- replay rejection
- signature verification failure rejection
- safe fallback when trust cannot be established

---

## 2. Current Test Architecture

Shyntr currently uses a layered strategy:

### Handler / boundary regression tests
Purpose:
- protect narrow protocol and security behaviors
- prove exact failure modes
- keep fixes bounded

### Repository-local E2E tests
Purpose:
- validate real HTTP trust boundaries
- validate real DB-backed flow continuity
- validate tenant propagation end-to-end
- validate federation continuity without relying on external infrastructure

### CI lane model
Purpose:
- keep PR feedback fast
- keep integration confidence broader
- keep release gates focused on security-critical golden scenarios

---

## 3. Implemented Coverage

## 3.1 OIDC Core E2E

Covered:
- discovery
- tenant-scoped authorize
- login accept
- consent accept
- authorization code issuance
- PKCE S256 token exchange
- userinfo
- logout redirect

Security value:
- proves the repository-local OIDC core path works through real handlers and persistence
- proves tenant-scoped routes are viable for the normal user journey

---

## 3.2 Tenant Isolation E2E

Covered:
- foreign authorization code rejected by another tenant token endpoint
- foreign access token rejected by another tenant userinfo endpoint
- foreign client rejected at authorize

Security value:
- proves cross-tenant flow confusion is rejected at the real boundary
- protects Shyntr’s primary security model

---

## 3.3 Exact Redirect URI Matching E2E

Covered:
- trailing slash mismatch rejected
- query string mismatch rejected
- host alias mismatch rejected

Security value:
- proves strict redirect URI matching at token exchange
- protects against open redirect and code misuse classes

---

## 3.4 Logout Security E2E

Covered:
- successful RP-initiated logout preserves state
- unregistered post_logout_redirect_uri is blocked
- malformed id_token_hint is blocked locally
- tenant-crossed id_token_hint does not produce unsafe redirect
- safe local fallback when logout request cannot be trusted

Security value:
- proves logout remains tenant-safe
- proves redirect safety on logout boundary
- locks in safe fallback behavior

---

## 3.5 OIDC Federation Callback E2E

Covered:
- federated login initiation
- callback handling
- valid state resumes original flow
- missing state rejected
- invalid state rejected
- tenant-crossed callback rejected
- continuation through login_verifier, consent, and final token issuance

Security value:
- proves federation callback continuity
- proves state-based trust restoration
- proves tenant-crossed callback rejection

---

## 3.6 SAML ACS E2E

Covered:
- SAML federated login initiation
- ACS POST handling
- valid RelayState resumes original flow
- missing RelayState rejected
- invalid RelayState rejected
- replayed assertion rejected
- tenant-crossed ACS rejected
- continuation through login_verifier, consent, and token issuance

Security value:
- proves RelayState continuity and replay protection
- proves cross-tenant ACS protection
- proves real bridge continuity through ACS

---

## 3.7 SAML SLO E2E

Covered:
- SP-initiated SLO request handling
- SLO response handling
- malformed SLO request rejection
- tenant-crossed SLO rejection
- safe local fallback when logout request cannot be trusted
- RelayState preservation on supported branches

Additional deterministic security regression:
- tampered signed logout request on the tenant-scoped IdP SLO route is rejected with invalid_signature
- rejection does not fall through to unsafe redirect behavior
- tenant scoping remains intact during the signature-failure path

Security value:
- proves logout signature trust boundary
- separates malformed-input rejection from signature-failure rejection
- locks in safe behavior under tampering

---

## 4. Confirmed Production-Side Fixes Introduced During Test Buildout

The following real boundary issues were identified and fixed while building the E2E program:

### 4.1 UserInfo tenant propagation fix
Issue:
- UserInfo introspection did not propagate the resolved tenant into request context consistently

Effect:
- tenant-bound token introspection could become fragile or incorrect

Fix:
- UserInfo now propagates tenant context before introspection, aligned with Authorize and Token behavior

### 4.2 Logout tenant isolation fix
Issue:
- tenant hints inside id_token_hint could override the route tenant in logout redirect handling

Effect:
- tenant-crossed logout redirect behavior could violate isolation expectations

Fix:
- route tenant remains authoritative for logout redirect handling

These fixes were confirmed and locked in by repository-local E2E coverage.

---

## 5. CI Lane Model

## 5.1 Fast Lane
Purpose:
- quick confidence on PRs
- avoid federation-sensitive broader runner behavior

Run pattern:
```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(CoreFlow|TenantIsolation|RedirectURIExactMatching|Logout_)' -count=1
````

Includes:

* OIDC core
* tenant isolation
* redirect URI exact matching
* logout security

Trigger:

* pull_request

---

## 5.2 Main Lane

Purpose:

* broader repository-local integration confidence on the active integration branch

Run pattern:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(CoreFlow|TenantIsolation|RedirectURIExactMatching|Logout_|FederationCallback|SAMLACS|SAMLSLO)' -count=1
```

Includes:

* fast lane tests
* OIDC federation callback
* SAML ACS
* SAML SLO

Trigger:

* develop branch integration workflow

---

## 5.3 Release Lane

Purpose:

* release-blocking auth trust-boundary verification

Run pattern:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(CoreFlow|TenantIsolation|RedirectURIExactMatching|Logout_|FederationCallback|SAMLACS|SAMLSLO)' -count=1
```

Optional stricter negative replay:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(TenantIsolation|RedirectURIExactMatching|Logout_)' -count=1
```

Trigger:

* release/tag build workflow

---

## 6. Golden Scenarios

The following scenarios should be treated as the current release-blocking golden set:

* `TestOIDCE2E_CoreFlow`
* `TestOIDCE2E_TenantIsolation`
* `TestOIDCE2E_RedirectURIExactMatching`
* `TestOIDCE2E_Logout_*`
* `TestOIDCE2E_FederationCallback`
* `TestOIDCE2E_SAMLACS`
* `TestOIDCE2E_SAMLSLO`

These are the smallest scenarios that currently prove the major Shyntr security and protocol boundaries.

---

## 7. Known Execution Notes

### Federation callback mixed-run limitation

Some broader mixed runs can hit local bind restrictions in constrained sandbox environments when the in-process fake OIDC provider attempts to bind on a local ephemeral port.

Implication:

* focused suites are the source of truth
* CI lane patterns must stay tight and intentional
* bind-sensitive runs should not be confused with protocol regressions

### Test concentration

A large portion of repository-local E2E coverage currently lives in:

* `internal/adapters/http/handlers/oidc_e2e_test.go`

This is acceptable for the current phase, but it should be monitored as coverage grows.

---

## 8. Rules for Future Test Work

### Always do

* classify the exact mismatch before fixing
* keep change surface minimal
* prefer real handler and persistence boundaries
* add regression coverage for every confirmed bug
* preserve tenant context explicitly across all trust boundaries
* test safe failure paths, not just happy paths

### Do not do

* do not change behavior just to satisfy tests
* do not broaden a bounded fix into unrelated refactors
* do not invent external test dependencies if repository-local fixtures are enough
* do not merge malformed-input tests and signature-failure tests into one ambiguous assertion
* do not weaken route-tenant authority using hints from untrusted input

---

## 9. Remaining High-Value Gaps

At the current stage, the first strong E2E security foundation is in place.

Remaining work should be chosen carefully and only when it materially improves trust-boundary confidence.

Examples of future work:

* release gate simplification decision:

    * broad repo gate vs golden-scenario gate
* potential decomposition of the large E2E test file into bounded thematic files
* additional deterministic negative cases only if they improve real release confidence
* future fuzz / chaos / performance layers if needed

---

## 10. Recommended Working Order for Future Changes

When adding or changing auth behavior:

1. identify the trust boundary
2. classify the mismatch
3. patch the smallest complete surface
4. add or update narrow regression coverage
5. add or extend E2E only if the boundary is security-critical or flow-critical
6. update lane documentation only if commands or scenario grouping changed

---

## 11. Summary

Shyntr now has a repository-local, deterministic, security-oriented E2E testing foundation that validates:

* protocol correctness
* strict tenant isolation
* bridge continuity
* redirect URI safety
* logout safety
* state / RelayState handling
* replay rejection
* signature failure rejection

This foundation is now connected to CI lane execution and documented as an operational part of the repository, not just an implementation detail.