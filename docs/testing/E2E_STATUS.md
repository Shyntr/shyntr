# Shyntr E2E Status

## Current State

The repository-local E2E suite currently validates the following security-critical and protocol-critical paths:

### OIDC Core
- discovery
- authorization code flow
- PKCE S256 token exchange
- tenant-scoped authorize/token/userinfo/logout
- exact redirect URI matching at token exchange

### Tenant Isolation
- foreign authorization code rejected by another tenant token endpoint
- foreign access token rejected by another tenant userinfo endpoint
- tenant-crossed client usage rejected at authorize

### Logout Security
- RP-initiated logout success path
- unregistered `post_logout_redirect_uri` blocked
- malformed `id_token_hint` blocked locally
- tenant-crossed `id_token_hint` does not produce unsafe redirect
- safe local fallback when logout request cannot be trusted

### OIDC Federation
- federated login initiation
- callback handling
- valid state resumes original flow
- missing state rejected
- invalid state rejected
- tenant-crossed callback rejected
- continuation through login_verifier, consent, and final token issuance

### SAML Federation
- SAML federated login initiation
- ACS POST handling
- valid RelayState resumes original flow
- missing RelayState rejected
- invalid RelayState rejected
- replayed assertion rejected
- tenant-crossed ACS rejected
- continuation through login_verifier, consent, and token issuance

### SAML SLO
- SP-initiated SLO request handling
- SLO response handling
- malformed SLO request rejection
- tenant-crossed SLO rejection
- safe local fallback when logout request cannot be trusted
- RelayState preservation on supported branches

---

## Lane Grouping

Workflow:

- [`.github/workflows/e2e-lanes.yml`](/Users/nevzatcirak/Developer/projects/shyntr/.github/workflows/e2e-lanes.yml)
- [`.github/workflows/dev.yml`](/Users/nevzatcirak/Developer/projects/shyntr/.github/workflows/dev.yml)
- [`.github/workflows/release.yml`](/Users/nevzatcirak/Developer/projects/shyntr/.github/workflows/release.yml)

### Fast Lane

Purpose:

- quick confidence for core OIDC and tenant-boundary regressions
- suitable for local preflight and short CI jobs

Command:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(CoreFlow|TenantIsolation|RedirectURIExactMatching|Logout_)' -count=1
```

### Main Lane

Purpose:

- broader repository-local E2E coverage
- includes the protocol-bridging scenarios in addition to the OIDC baseline

Command:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(CoreFlow|TenantIsolation|RedirectURIExactMatching|Logout_|FederationCallback|SAMLACS|SAMLSLO)' -count=1
```

### Release Lane

Purpose:

- must-pass release gate for the current E2E golden scenarios
- blocks release on regressions in tenant isolation, redirect safety, logout safety, federation continuity, and SAML trust boundaries

Command:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(CoreFlow|TenantIsolation|RedirectURIExactMatching|Logout_|FederationCallback|SAMLACS|SAMLSLO)' -count=1
```

### Optional Stricter Negative Replay

Purpose:

- additional focused negative pass for the strictest tenant and redirect security boundaries

Command:

```bash
go test ./internal/adapters/http/handlers -run 'TestOIDCE2E_(TenantIsolation|RedirectURIExactMatching|Logout_)' -count=1
```

---

## Release-Blocking Security Invariants Covered

- strict tenant isolation
- PKCE enforcement
- exact redirect URI matching
- callback state validation
- RelayState validation
- replay rejection for SAML ACS
- logout redirect safety

### Release-Blocking Test Set

The following scenarios are the release-blocking golden suite for this snapshot:

- `TestOIDCE2E_CoreFlow`
- `TestOIDCE2E_TenantIsolation`
- `TestOIDCE2E_RedirectURIExactMatching`
- `TestOIDCE2E_Logout_*`
- `TestOIDCE2E_FederationCallback`
- `TestOIDCE2E_SAMLACS`
- `TestOIDCE2E_SAMLSLO`

---

## Remaining Gaps

### High Priority
- deterministic SAML SLO signature verification failure coverage
- stable golden-scenario grouped execution for release lane

### Medium Priority
- broader mixed-suite execution without sandbox-local bind issues
- additional negative federation edge cases where useful

### Lower Priority
- expanded bridge scenario catalog
- future fuzz / chaos / performance layers

---

## Golden Scenarios

The following scenarios should become the release-lane must-pass suite:

- `TestOIDCE2E_CoreFlow`
- `TestOIDCE2E_TenantIsolation`
- `TestOIDCE2E_RedirectURIExactMatching`
- `TestOIDCE2E_Logout_*`
- `TestOIDCE2E_FederationCallback`
- `TestOIDCE2E_SAMLACS`
- `TestOIDCE2E_SAMLSLO`

---

## Execution Guidance

### Known Sandbox Limitation

- Mixed runs that include federation callback coverage can hit a local bind restriction in this sandbox when the in-process fake OIDC provider tries to start on `127.0.0.1:0`.
- When that happens, prefer the focused lanes above instead of a broad mixed run.

### Fast Lane
- OIDC core E2E
- tenant isolation E2E
- redirect URI exact matching
- logout E2E

### Main Lane
- OIDC core E2E
- tenant isolation E2E
- redirect URI exact matching
- logout E2E
- OIDC federation callback
- SAML ACS
- SAML SLO

### Release Lane
- all golden scenarios listed above
- release-blocking tenant and redirect negatives
- federation callback
- SAML ACS
- SAML SLO

---

## Notes

- The E2E suite is intentionally repository-local and deterministic.
- In-process fixtures are preferred over Docker where practical.
- Focused suites are the source of truth when broader mixed runs are affected by local sandbox bind restrictions.
- Production changes should only be made when a real boundary failure is confirmed by the tests.
