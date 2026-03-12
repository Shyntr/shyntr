# Shyntr CLI Reference Guide

The Shyntr Identity Hub includes a powerful Command Line Interface (CLI) built into the main binary. It allows administrators to manage tenants, configure OIDC/SAML clients, and register external identity providers without directly accessing the database or API.

## Usage Syntax

```bash
./shyntr [command] [flags]
```

---

## 1. System Commands

These commands are used to manage the core application state.

### `migrate`
Runs the GORM database auto-migration to ensure all schema definitions are up to date and seeds default system scopes.

* **Usage:** `./shyntr migrate`
* **Flags:** None

### `serve`
Starts the public and admin HTTP servers, including background cleanup workers.

* **Usage:** `./shyntr serve`
* **Flags:** None

---

## 2. Tenant Management

Tenants are the core isolation boundaries within Shyntr.

### `create-tenant`
Creates a new isolated tenant environment.

* **Usage:** `./shyntr create-tenant [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--id` | No | *Auto-generated 4-byte hex* | The unique slug identifier for the tenant. |
| `--name` | No | *Same as `--id`* | The operational name of the tenant. |
| `--display-name` | No | *Same as `--name`* | The human-readable display name. |
| `--desc` | No | `CLI Created` | A short description of the tenant's purpose. |

### `get-tenant`, `update-tenant`, `delete-tenant`
* **Get Usage:** `./shyntr get-tenant [id]`
* **Update Usage:** `./shyntr update-tenant [id] [--name] [--display-name]`
* **Delete Usage:** `./shyntr delete-tenant [id]` *(Note: The default tenant cannot be deleted).*

---

## 3. Scope Management (New)

Scopes define the permissions and claims that can be requested by applications.

### `create-scope`
Creates a new scope for a specific tenant.

* **Usage:** `./shyntr create-scope [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--name` | **Yes** | - | The unique name of the scope (e.g., `email`, `read:api`). |
| `--tenant-id` | No | `default` | The ID of the tenant this scope belongs to. |
| `--desc` | No | - | A short description of the scope's purpose. |
| `--claims` | No | - | Comma-separated list of user attributes mapped to this scope (e.g., `email,email_verified`). |
| `--system` | No | `false` | Set to true if this is a protected system scope. |

### `get-scope`, `update-scope`, `delete-scope`
* **Get Usage:** `./shyntr get-scope [id]`
* **Update Usage:** `./shyntr update-scope [id] [--name] [--desc] [--claims]`
* **Delete Usage:** `./shyntr delete-scope [id]` *(Note: System scopes cannot be deleted via CLI).*

---

## 4. OIDC Client Management

Manage applications (Service Providers) that will authenticate users via OpenID Connect or OAuth2.

### `create-client`
Registers a new OIDC client.

* **Usage:** `./shyntr create-client [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--tenant-id` | No | `default` | The ID of the tenant this client belongs to. |
| `--client-id` | No | *Auto-generated 8-byte hex* | The unique Client ID. |
| `--name` | No | `New Client <id>` | The descriptive name of the application. |
| `--secret` | No | *Auto-generated 16-byte hex* | The Client Secret (ignored if `--public` is true). |
| `--redirect-uris` | No | `http://localhost:8080/callback` | Comma-separated list of allowed callback URLs. |
| `--post-logout-uris` | No | - | Comma-separated exact URIs allowed for redirection after logout. |
| `--scopes` | No | `openid, profile, email, offline_access` | Comma-separated scopes allowed for this client. |
| `--audience` | No | - | Comma-separated requested audiences. |
| `--public` | No | `false` | Set to true for SPA/Mobile apps (disables secret, enforces PKCE). |
| `--skip-consent` | No | `false` | Skip the user consent screen during authorization. |

### `get-client`, `update-client`, `delete-client`
* **Get Usage:** `./shyntr get-client [client_id]`
* **Update Usage:** `./shyntr update-client [client_id] [--name] [--redirect-uris] [--post-logout-uris] [--scopes] [--secret]`
* **Delete Usage:** `./shyntr delete-client [client_id]`

---

## 5. SAML Client (Service Provider) Management

Manage legacy applications that require SAML 2.0 authentication.

### `create-saml-client`
Registers a new SAML Service Provider.

* **Usage:** `./shyntr create-saml-client [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--entity-id` | **Yes** | - | The exact Entity ID expected by the Service Provider. |
| `--acs-url` | **Yes** | - | The Assertion Consumer Service (ACS) URL where SAML Responses are sent. |
| `--slo-url` | No | - | Single Logout (SLO) Service URL of the application. |
| `--allowed-scopes`| No | - | Comma-separated scopes defining which user attributes (claims) to send. |
| `--tenant-id` | No | `default` | The ID of the tenant this client belongs to. |
| `--name` | No | `SAML App` | The descriptive name of the application. |
| `--force-authn` | No | `false` | Force the user to re-authenticate regardless of active sessions. |

### `get-saml-client`, `update-saml-client`, `delete-saml-client`
* **Get Usage:** `./shyntr get-saml-client [entity_id]`
* **Update Usage:** `./shyntr update-saml-client [entity_id] [--name] [--acs-url] [--slo-url] [--allowed-scopes]`
* **Delete Usage:** `./shyntr delete-saml-client [entity_id]`

---

## 6. SAML Connection (Identity Provider) Management

Manage external SAML Identity Providers (like corporate ADFS or Keycloak) that Shyntr will trust.

### `create-saml-connection`
Registers a new external SAML IdP using its Metadata XML or URL.

* **Usage:** `./shyntr create-saml-connection [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--metadata-file` | **Yes*** | - | Local file path to the SAML IdP's metadata XML file. |
| `--metadata-url` | **Yes*** | - | URL to dynamically fetch and parse the metadata XML. |
| `--tenant-id` | No | `default` | The ID of the tenant this connection belongs to. |
| `--name` | No | `SAML IDP` | The descriptive name of the Identity Provider. |
| `--sign-request` | No | `false` | Sign outbound AuthnRequests sent to this IdP. |

*\* Either `--metadata-file` or `--metadata-url` MUST be provided.*

### `get-saml-connection`, `delete-saml-connection`
* **Get Usage:** `./shyntr get-saml-connection [id]`
* **Delete Usage:** `./shyntr delete-saml-connection [id]`

---

## 7. OIDC Connection (Identity Provider) Management

Manage external OpenID Connect Identity Providers (like Google, Azure AD) that Shyntr will trust.

### `create-oidc-connection`
Registers a new external OIDC Provider.

* **Usage:** `./shyntr create-oidc-connection [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--issuer` | **Yes** | - | The exact Issuer URL of the external OIDC Provider (used for discovery). |
| `--client-id` | **Yes** | - | The Client ID provided by the external IdP. |
| `--client-secret` | **Yes** | - | The Client Secret provided by the external IdP. |
| `--tenant-id` | No | `default` | The ID of the tenant this connection belongs to. |
| `--name` | No | `OIDC Provider` | The descriptive name of the Identity Provider. |
| `--scopes` | No | `openid, profile, email` | Comma-separated scopes requested from the external IdP. |

### `get-oidc-connection`, `delete-oidc-connection`
* **Get Usage:** `./shyntr get-oidc-connection [id]`
* **Delete Usage:** `./shyntr delete-oidc-connection [id]`