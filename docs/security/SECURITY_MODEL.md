# Shyntr Security Philosophy & Zero Trust Model

## Purpose

This document defines the security philosophy behind Shyntr and the principles that guide all authentication, authorization, and identity routing decisions.

Shyntr is designed as a **Zero Trust identity routing layer**, where every boundary is treated as untrusted unless explicitly validated.

---

## 1. Core Philosophy

Shyntr follows one fundamental rule:

> Never trust identity context. Always verify it at the boundary.

This applies to:
- users
- services
- tokens
- federation inputs (OIDC, SAML)
- internal transitions between flows

---

## 2. Zero Trust Principles in Shyntr

### 2.1 Tenant Isolation is a Hard Security Boundary

- Every request is scoped to a tenant through the route
- Route tenant is authoritative
- No input (token, hint, assertion) can override route tenant
- Cross-tenant flow reuse is always rejected

Examples:
- foreign authorization code → rejected
- foreign access token → rejected
- cross-tenant logout context → rejected

---

### 2.2 Trust is Established Only Through Verified State

Shyntr does not rely on implicit continuity.

Instead, it uses:
- OAuth2 `state`
- OIDC flow context
- SAML `RelayState`

Rules:
- state must exist
- state must match
- state must be bound to the correct tenant and flow

If not:
→ request is rejected

---

### 2.3 Exact Matching Over Fuzzy Matching

Shyntr enforces strict equality where it matters:

- redirect URIs must match exactly
- client identity must match exactly
- issuer expectations must match exactly

No:
- partial matching
- host aliasing
- implicit normalization

---

### 2.4 Safe Failure Over Implicit Recovery

If trust cannot be established:

- do not continue the flow
- do not attempt best-effort recovery
- do not redirect to potentially unsafe locations

Instead:
→ fail closed

Examples:
- malformed `id_token_hint` → local safe logout
- invalid RelayState → reject
- invalid signature → reject
- unknown client → reject

---

### 2.5 Signature Verification is Mandatory

For all signed inputs:

- signatures must be valid
- signature context must match expected tenant and issuer

Invalid signature:
→ reject immediately

No fallback behavior is allowed after signature failure.

---

### 2.6 Replay is Always Treated as Malicious

- SAML assertions are one-time use
- replay attempts are rejected

No:
- tolerance
- grace reuse
- partial acceptance

---

### 2.7 Federation is a Controlled Trust Bridge

Shyntr acts as a bridge between identity protocols:
- OIDC ↔ SAML
- legacy ↔ modern systems

But:
- external identity providers are not trusted by default
- all federation inputs must pass boundary validation

Trust is restored only after:
- state validation
- tenant validation
- signature validation (if applicable)

---

### 2.8 Logout is a High-Risk Boundary

Logout is treated as a sensitive operation because it involves:

- session invalidation
- user redirection
- potential cross-tenant confusion

Shyntr enforces:
- strict redirect validation
- tenant-bound logout handling
- safe fallback behavior

---

## 3. Trust Boundaries in Shyntr

Each of the following is treated as a separate security boundary:

- `/oauth2/auth`
- `/oauth2/token`
- `/userinfo`
- `/logout`
- `/t/{tenant}/oidc/callback`
- `/t/{tenant}/saml/sp/acs`
- `/t/{tenant}/saml/sp/slo`

Every boundary:
- validates tenant
- validates input integrity
- validates flow continuity

---

## 4. Security Invariants

The following invariants must always hold:

- tenant context is never overridden by untrusted input
- redirect URIs are exact-match validated
- state / RelayState must match and be valid
- signatures must be verified
- replay must be rejected
- logout must not produce unsafe redirect
- failed validation must not continue the flow

These invariants are enforced by:
- handler logic
- repository-local E2E tests
- CI release lanes

---

## 5. Testing as a Security Mechanism

Shyntr treats testing as part of its security model.

### Why

Because:
- many vulnerabilities appear at flow boundaries
- integration bugs are security bugs in identity systems

### How

Shyntr uses:
- repository-local E2E tests
- deterministic flows
- real handler + persistence paths

### What is verified

- protocol correctness
- tenant isolation
- federation continuity
- redirect safety
- replay protection
- signature failure handling

See:
docs/testing/TEST_ARCHITECTURE_PROGRESS.md

---

## 6. CI as a Security Gate

Shyntr enforces security through CI lanes:

### Fast Lane (PR)
- protects critical boundaries quickly

### Main Lane (integration)
- validates broader flow interactions

### Release Lane
- acts as a security gate
- must pass before release

Security is not assumed.
It is continuously revalidated.

---

## 7. Design Rules for Contributors

When modifying or adding features:

### Always:
- identify the trust boundary
- validate tenant context explicitly
- validate all external input
- fail closed on uncertainty
- add regression tests for any bug

### Never:
- trust client-provided context
- allow implicit cross-tenant behavior
- weaken redirect validation
- continue after signature failure
- introduce silent fallback behavior

---

## 8. Summary

Shyntr is not just an identity router.

It is a **Zero Trust identity enforcement layer** that:

- treats every boundary as untrusted
- validates every transition explicitly
- rejects unsafe behavior deterministically
- enforces security through tests and CI

Security is not an add-on.

It is the foundation of the system.