---
name: shyntr-iam
description: Deep domain expertise for OAuth2, OIDC, and SAML protocols within Shyntr. Use when designing new auth flows, debugging complex protocol mismatches, or auditing trust boundaries.
---

# Shyntr IAM & Protocol Expert

Use this skill when dealing with complex authentication and authorization logic.

## Protocol Specifics

### OAuth2 / OIDC
- **Trust Boundary**: The `/token` endpoint is the primary trust boundary.
- **PKCE**: Mandatory for public clients. Check for `code_challenge` and `code_verifier` validation.
- **Redirect URIs**: Must be exactly matched. No partial or wildcard matches unless explicitly allowed by config.
- **Claims**: Ensure claims mapping follows OIDC specs and tenant-specific overrides.

### SAML 2.0
- **Assertions**: Verify signature and encryption status.
- **Replay Protection**: Check if the assertion ID has been processed before (see `cache_saml_replay_repository.go`).
- **Bindings**: Support for Redirect and POST bindings.

## Multi-Tenancy Rules
- Every IAM operation MUST start with identifying the tenant from the context or URL.
- Never leak metadata or session state between tenants.
- Validation should check if the `client_id` belongs to the `tenant_id` before any protocol logic begins.

## Key Files to Reference
- `internal/application/security/`: Core security logic.
- `internal/adapters/iam/`: Fosite and SAML integration.
- `internal/domain/model/`: Tenant, Client, and Session models.
