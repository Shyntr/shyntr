# ADR-001: Do Not Support IdP-Initiated (Unsolicited) SAML Responses

## Status

Accepted

## Context

IdP-initiated SAML introduces security and flow ambiguity because the Service Provider receives a SAML Response without a prior AuthnRequest.

This creates several risks:

* Login CSRF (unsolicited authentication)
* Session fixation / confused deputy scenarios
* Tenant confusion (issuer collision across tenants)
* Replay attack surface expansion
* Ambiguous flow branching
* Violation of OAuth2/OIDC trust boundaries

## Decision

Shyntr will not support IdP-initiated SAML responses.

All authentication flows MUST be:

* Explicitly initiated by the client (SP-initiated)
* Routed through the standard login / authorization pipeline
* Bound to a verifiable request context

Any SAML Response received without a valid request context will be rejected.

## Consequences

### Positive

* Eliminates login CSRF attack vector
* Preserves strict tenant isolation guarantees
* Ensures all sessions originate from verified flows
* Simplifies reasoning about authentication state
* Aligns fully with OAuth2 / OIDC flow expectations

### Negative

* Some legacy integrations may require adaptation (SP-initiated flow)

## Implementation Notes

* Reject SAML responses without a matching login transaction
* Ensure the ACS handler enforces strict request correlation

## References

* SAML 2.0 Core Specification
* OAuth 2.0 Authorization Framework (RFC 6749)
* OpenID Connect Core 1.0
