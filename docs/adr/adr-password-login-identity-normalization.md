# ADR: Password Login Identity Normalized Envelope

**Status:** Proposed
**Version:** v1.1+
**Date:** 2026-04-23

---

## 1. Context

Shyntr acts as a protocol-agnostic identity router, bridging authentication flows across:

* OAuth2 / OIDC
* SAML
* LDAP (via providers)
* External identity systems

With the introduction of the **Password Method via external verifier**, the authentication flow is now split across:

* **Auth Portal** (UI layer)
* **Password Verifier** (credential validation boundary)
* **Shyntr Backend** (identity routing + protocol projection)

The current flow:

1. Auth Portal sends `username/password` to the external Password Verifier via `login_url`
2. Verifier validates credentials against an external identity source
3. Verifier calls Shyntr’s login accept endpoint
4. Shyntr continues the authentication flow (consent → token/assertion issuance)

At this stage, user authentication is completed successfully.
However, there is no standardized mechanism for propagating **user identity attributes** and **authentication metadata** into Shyntr.

This prevents consistent generation of:

* OIDC ID Tokens
* OAuth2 Access Tokens
* UserInfo responses
* SAML Assertions (AttributeStatement, NameID, AuthnContext)

---

## 2. Problem

Without a standardized identity contract between the Password Verifier and Shyntr:

* Attribute names vary across verifiers (`mail`, `email`, `userPrincipalName`, etc.)
* `subject` semantics become inconsistent
* Username, email, and immutable identifiers get conflated
* Group and role semantics diverge
* Token and assertion outputs become verifier-dependent
* Tenant isolation may be indirectly compromised
* Claim governance becomes unmanageable

Most importantly:

> Shyntr risks losing its role as a protocol-agnostic identity router and becomes verifier-dependent.

---

## 3. Decision

Shyntr introduces a **Normalized Identity Envelope** as the only accepted identity contract between external verifiers and the backend.

The architecture is explicitly separated as follows:

### 3.1 Responsibilities

* **Password Verifier**

    * Authenticates user credentials
    * Loads identity profile from external source
    * Normalizes identity into a common envelope

* **Shyntr Backend**

    * Validates login challenge and tenant ownership
    * Stores normalized identity in authentication context
    * Projects identity into protocol-specific outputs (OIDC, SAML, etc.)

* **Auth Portal**

    * Transports credentials only
    * Does not produce or modify identity attributes

---

## 4. Normalized Identity Envelope

The Password Verifier MUST send a normalized identity payload when accepting login.

### 4.1 Envelope structure

```json
{
  "subject": "ext:12345",
  "identity": {
    "attributes": {
      "preferred_username": "alice@example.com",
      "email": "alice@example.com",
      "email_verified": true,
      "given_name": "Alice",
      "family_name": "Doe",
      "name": "Alice Doe"
    },
    "groups": ["engineering", "admins"],
    "roles": []
  },
  "authentication": {
    "amr": ["pwd"],
    "acr": "urn:shyntr:loa:1",
    "authenticated_at": "2026-04-23T18:30:00Z"
  }
}
```

---

## 5. Field semantics

### 5.1 Subject (REQUIRED)

* Must be a **stable, immutable identifier**
* Must NOT be derived from:

    * username
    * email
    * login name

Valid examples:

* database user ID
* LDAP objectGUID
* employeeNumber
* external UUID

This ensures identity stability across time and tenants.

---

### 5.2 Attributes

`identity.attributes` contains normalized, protocol-agnostic fields.

Canonical mappings:

| Canonical field    | Typical source aliases                           |
| ------------------ | ------------------------------------------------ |
| preferred_username | uid, username, samAccountName, userPrincipalName |
| email              | mail, email, userPrincipalName                   |
| given_name         | givenName, first_name                            |
| family_name        | sn, surname, last_name                           |
| name               | displayName, cn, full_name                       |

Custom attributes are allowed and must remain inside the attributes map.

---

### 5.3 Groups vs Roles

These are intentionally separated:

* `groups`: raw membership data from identity source
* `roles`: application or tenant-level authorization labels

If the source only provides groups:

* populate `groups`
* leave `roles` empty

Role derivation is not required at the verifier level.

---

### 5.4 Authentication metadata

Minimum required:

* `amr` (Authentication Methods Reference)
* `authenticated_at`

Recommended:

* `acr` (Authentication Context Class Reference)

Example:

```json
{
  "amr": ["pwd"]
}
```

---

## 6. Accept Login Boundary

The login accept endpoint is extended to include the normalized identity envelope.

Example:

```json
{
  "subject": "ext:12345",
  "remember": false,
  "remember_for": 3600,
  "context": {
    "identity": { ... },
    "authentication": { ... }
  }
}
```

Shyntr MUST:

1. Validate required fields
2. Validate tenant ownership via `login_challenge`
3. Persist the normalized identity into the auth request context
4. Make it available for downstream processing

---

## 7. Projection Model

Shyntr uses the normalized identity as the single source of truth.

### 7.1 OIDC

Produces:

* `sub`
* `preferred_username`
* `email`
* `name`
* `given_name`
* `family_name`
* `groups`
* `roles`
* `amr`
* `acr`

### 7.2 Access Token

Produces a reduced set:

* `sub`
* `tenant`
* `scope`
* `roles`
* `groups`

### 7.3 UserInfo

Produces a richer identity view.

### 7.4 SAML Assertion

Maps normalized attributes into:

* AttributeStatement
* NameID
* AuthnContext

Projection MUST be:

* policy-driven
* client-aware
* scope-aware

---

## 8. Security Considerations

### 8.1 Trust boundary

The Password Verifier is a **trusted boundary** for identity:

* Only verifier validates credentials
* Portal is not trusted for identity attributes
* Shyntr validates tenant ownership independently

---

### 8.2 Logging restrictions

The system MUST NOT log:

* raw passwords
* raw credential payloads
* raw upstream identity responses
* full normalized identity payloads

---

### 8.3 Claim projection control

Shyntr MUST NOT blindly include all attributes in tokens.

Projection must be:

* explicitly controlled
* policy-based
* minimal by default

---

### 8.4 Tenant isolation

* Identity context is bound to the login challenge
* Cross-tenant leakage MUST be prevented
* Subject must not collide across tenants without isolation context

---

## 9. Consequences

### Positive

* Unified identity model across all verifiers
* Clean separation of concerns
* Protocol-agnostic core preserved
* Enables future claim governance and policy engines
* Simplifies OIDC/SAML dual support

### Trade-offs

* Verifier implementation becomes slightly more complex
* Requires strict schema validation
* Introduces new persistence and mapping responsibilities

---

## 10. Alternatives Considered

### A. Portal carries identity attributes

Rejected
→ Breaks trust boundaries and mixes UI with identity authority

### B. Store raw external profiles

Rejected
→ Couples Shyntr to external schemas

### C. Verifier produces tokens/assertions

Rejected
→ Breaks protocol abstraction and central control

---

## 11. Implementation Strategy

### Phase 1 (PR1)

* Accept normalized identity envelope
* Validate required fields
* Persist into auth request context

### Phase 2

* OIDC projection (ID token, access token, userinfo)

### Phase 3

* SAML projection

---

## 12. Summary

> The verifier normalizes identity.
> Shyntr projects identity.

This separation preserves Shyntr’s core design as a **protocol-agnostic identity router** while enabling secure and consistent identity propagation.