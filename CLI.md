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
Runs the GORM database auto-migration to ensure all schema definitions are up to date, seeds default system scopes, and initializes the default global outbound security policies.

In addition to schema migration, this command also ensures that a **global outbound policy** is initialized.

This policy acts as a secure default fallback when no tenant-specific outbound policy is defined.

The global policy enforces:

* HTTPS-only outbound communication
* Blocking of private, loopback, and link-local IP ranges
* DNS resolution requirement before requests
* Disabled redirects
* Strict timeout and response size limits

This guarantees that all outbound interactions comply with Zero Trust networking principles by default.

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
| `--id` | No | *Auto-generated UUID* | The unique slug identifier for the tenant. |
| `--name` | No | *Same as `--id`* | The operational name of the tenant. |
| `--display-name` | No | *Same as `--name`* | The human-readable display name. |
| `--desc` | No | `CLI Created` | A short description of the tenant's purpose. |

### `get-tenant`, `update-tenant`, `delete-tenant`
* **Get Usage:** `./shyntr get-tenant [id]`
* **Update Usage:** `./shyntr update-tenant [id] [--name] [--display-name]`
* **Delete Usage:** `./shyntr delete-tenant [id]` *(Note: The default tenant cannot be deleted).*

---

## 3. Scope Management

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
| :--- |:---------| :--- | :--- |
| `--tenant-id` | No       | `default` | The ID of the tenant this client belongs to. |
| `--client-id` | No      | *Auto-generated UUID* | The unique Client ID. |
| `--name` | No      | `New Client <id>` | The descriptive name of the application. |
| `--secret` | No       | *Auto-generated 32-byte hex* | The Client Secret (ignored if `--public` is true). |
| `--auth-method` | No       | `client_secret_basic` for confidential clients, `none` for public clients | The token endpoint authentication method. |
| `--redirect-uris` | No      | `http://localhost:8080/callback` | Comma-separated list of allowed callback URLs. |
| `--post-logout-uris` | No       | - | Comma-separated exact URIs allowed for redirection after logout. |
| `--scopes` | No       | `openid, profile, email, offline_access` | Comma-separated scopes allowed for this client. |
| `--audience` | No       | - | Comma-separated requested audiences. |
| `--public` | No       | `false` | Set to true for SPA/Mobile apps (disables secret, enforces PKCE). |
| `--skip-consent` | No       | `false` | Skip the user consent screen during authorization. |

### `get-client`, `update-client`, `delete-client`
* **Get Usage:** `./shyntr get-client [client_id]`
* **Update Usage:** `./shyntr update-client [client_id] [--name] [--redirect-uris] [--post-logout-uris] [--scopes] [--secret]`
* **Delete Usage:** `./shyntr delete-client [client_id]`

### `inject-jwks`
Directly injects a JWKS payload into an existing client's database record.

* **Usage:** `./shyntr inject-jwks [client_id] [jwks_file]`
* **Flags:** None

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
| `--sign-response` | No | `false` | Sign the SAML response. |
| `--sign-assertion` | No | `false` | Sign SAML assertions. |

### `get-saml-client`, `update-saml-client`, `delete-saml-client`
* **Get Usage:** `./shyntr get-saml-client [entity_id]`
* **Update Usage:** `./shyntr update-saml-client [entity_id] [--name] [--acs-url] [--slo-url] [--allowed-scopes]`
* **Delete Usage:** `./shyntr delete-saml-client [entity_id]`

---

## 6. SAML Connection (Identity Provider) Management

Manage external SAML Identity Providers (like corporate ADFS or Keycloak) that Shyntr will trust.

### `create-saml-connection`
Registers a new external SAML IdP using its Metadata XML or URL.

> **Security Note:** If `--metadata-url` is used, Shyntr validates the outbound request using the configured outbound policy rules before fetching metadata.

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

> **Security Note:** The `--issuer` URL is validated against outbound policy restrictions before the connection is created.

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

---

## 8. LDAP Connection Management

Manage external LDAP or Active Directory directory connections that Shyntr will trust.

### `create-ldap-connection`
Registers a new LDAP directory connection.

* **Usage:** `./shyntr create-ldap-connection [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--tenant-id` | No | `default` | The ID of the tenant this connection belongs to. |
| `--name` | No | `LDAP Directory` | The descriptive name of the connection. |
| `--server-url` | **Yes** | - | LDAP server URL using `ldap://` or `ldaps://`. |
| `--bind-dn` | No | - | Service account bind DN. |
| `--bind-password` | No | - | Service account bind password. |
| `--base-dn` | **Yes** | - | Base DN for searches. |
| `--start-tls` | No | `false` | Use StartTLS with `ldap://`. |
| `--insecure-skip-verify` | No | `false` | Skip TLS certificate verification. |

### `get-ldap-connection`, `delete-ldap-connection`
* **Get Usage:** `./shyntr get-ldap-connection [id] --tenant-id <tenant_id>`
* **Delete Usage:** `./shyntr delete-ldap-connection [id] --tenant-id <tenant_id>`

---

## 9. Cryptographic Key Management

The Shyntr Identity Hub features a Zero-Downtime Key Rotation engine. By default, it operates in **Auto-Rollover** mode, automatically generating and rotating self-signed X.509 certificates and RSA keys.

For High-Assurance (PKI) environments where a central Certificate Authority (CA) must sign all SAML/OIDC keys, administrators must disable `AUTO_KEY_ROTATION_ENABLED` in the environment configuration and manually inject CA-signed keys using the CLI.

### `import-key`
Injects a CA-signed keypair into the Identity Hub. This command safely demotes the currently active key to a `PASSIVE` state (to decrypt inflight tokens) and immediately activates the new CA-signed key.

* **Usage:** `./shyntr import-key [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `--use` | No | `sig` | The cryptographic purpose of the key. Use `sig` for Signing (JWTs/SAML) or `enc` for Decryption (JWE). |
| `--cert` | **Yes** | - | Local file path to the CA-signed X.509 certificate (in PEM format). |
| `--key` | **Yes** | - | Local file path to the unencrypted RSA private key (in PEM format). |

#### Command Example (High-Assurance NATO/PKI Workflow)
```bash
# Inject a CA-signed key for Token Signing (SAML Assertions & OIDC ID Tokens)
./shyntr import-key --use sig --cert /etc/pki/tls/certs/nato-idp-signed.pem --key /etc/pki/tls/private/nato-idp-private.key

# Inject a CA-signed key for Token Decryption (Incoming JWEs)
./shyntr import-key --use enc --cert /etc/pki/tls/certs/nato-enc-signed.pem --key /etc/pki/tls/private/nato-enc-private.key
```

(Note: The imported private key is immediately encrypted with AES-256-GCM before being stored in the database. The raw file is only read once and is never stored in plaintext).

#### Expected File Formats
The CLI strictly expects PEM-encoded Base64 files. Binary formats (like DER or PFX) are not supported directly and must be converted using OpenSSL prior to import.

1. **Private Key File (.key):**
   Must be an unencrypted PKCS#1 or PKCS#8 RSA Private Key.

```plaintext
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0iN5yD87W8bWhzss5Uz4B13JM/XHbdbpyXppUGkbp1WBrLWR
lPPZTXGE7rCbZs6mZAQPWVTYr3pBU2u0NbLWmPPIVY+e+sGfPvMfiP117kW9xbEN
... (base64 encoded private key data) ...
x3jUrEqOaqQu1WgUWnFXOAvI/GA4TuZT1FAmD0XoRE4qZCX/94II+w==
-----END RSA PRIVATE KEY-----
```

2. **Certificate File (.pem or .crt):**
   Must be a valid X.509 Certificate signed by your trusted Certificate Authority.

```plaintext
-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIIGJ34EZ8uUkgwDQYJKoZIhvcNAQELBQAwJzElMCMGA1UE
AxMcU2h5bnRyIEdsb2JhbCBJZGVudGl0eSAtIHNpZzAeFw0yNjAzMTgxNTA4NDJa
... (base64 encoded certificate data) ...
aTgWweshVJVnmdgQtL/0Z4wBlMwunQmJ1cM9WeKmnRV0Z9vHr0Lyat3xm25D9/m+
jEEFmQ0y+PiwcH1B4xfu64t7ZO5GSOvh0Cmd+VQWg0NEGL+WY5Pp2cWiobVN5FDC
-----END CERTIFICATE-----
```
