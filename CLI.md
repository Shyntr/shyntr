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

Runs the GORM database auto-migration to ensure all schema definitions are up to date.

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
| --- | --- | --- | --- |
| `--id` | No | *Auto-generated 4-byte hex* | The unique slug identifier for the tenant. |
| `--name` | No | *Same as `--id*` | The operational name of the tenant. |
| `--display-name` | No | *Same as `--name*` | The human-readable display name. |
| `--desc` | No | `CLI Created` | A short description of the tenant's purpose. |

### `get-tenant`

Retrieves the details of a specific tenant.

* **Usage:** `./shyntr get-tenant [id]`
* **Arguments:** `id` (Required) - The unique ID of the tenant.

### `update-tenant`

Updates an existing tenant's configuration.

* **Usage:** `./shyntr update-tenant [id] [flags]`
* **Arguments:** `id` (Required) - The unique ID of the tenant.
* **Flags:** `--name`, `--display-name`

### `delete-tenant`

Deletes a tenant and cascades the deletion to all associated clients and connections. **Note:** The `default` tenant cannot be deleted.

* **Usage:** `./shyntr delete-tenant [id]`
* **Arguments:** `id` (Required) - The unique ID of the tenant.

---

## 3. OIDC Client Management

Manage applications (Service Providers) that will authenticate users via OpenID Connect or OAuth2.

### `create-client`

Registers a new OIDC client.

* **Usage:** `./shyntr create-client [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--tenant-id` | No | `default` | The ID of the tenant this client belongs to. |
| `--client-id` | No | *Auto-generated 8-byte hex* | The unique Client ID. |
| `--name` | No | `New Client <client-id>` | The descriptive name of the application. |
| `--secret` | No | *Auto-generated 16-byte hex* | The Client Secret (ignored if `--public` is true). |
| `--redirect-uris` | No | `http://localhost:8080/callback` | Comma-separated list of allowed callback URLs. |
| `--public` | No | `false` | Set to true for SPA/Mobile apps (disables secret and sets auth method to `none`). |

### `get-client`

Retrieves details of an OIDC client.

* **Usage:** `./shyntr get-client [client_id]`

### `update-client`

Updates an OIDC client's configuration.

* **Usage:** `./shyntr update-client [client_id] [flags]`
* **Flags:** `--name`, `--redirect-uris`, `--secret`

### `delete-client`

Deletes an OIDC client.

* **Usage:** `./shyntr delete-client [client_id]`

---

## 4. SAML Client (Service Provider) Management

Manage legacy applications that require SAML 2.0 authentication.

### `create-saml-client`

Registers a new SAML Service Provider.

* **Usage:** `./shyntr create-saml-client [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--entity-id` | **Yes** | - | The exact Entity ID expected by the Service Provider. |
| `--acs-url` | **Yes** | - | The Assertion Consumer Service (ACS) URL where SAML Responses are sent via POST. |
| `--tenant-id` | No | `default` | The ID of the tenant this client belongs to. |
| `--name` | No | `SAML App` | The descriptive name of the application. |

### `get-saml-client`

Retrieves details of a SAML Client.

* **Usage:** `./shyntr get-saml-client [entity_id]`

### `update-saml-client`

Updates a SAML Client's configuration.

* **Usage:** `./shyntr update-saml-client [entity_id] [flags]`
* **Flags:** `--acs-url`, `--name`

### `delete-saml-client`

Deletes a SAML Client.

* **Usage:** `./shyntr delete-saml-client [entity_id]`

---

## 5. SAML Connection (Identity Provider) Management

Manage external SAML Identity Providers (like corporate ADFS or Okta) that Shyntr will trust.

### `create-saml-connection`

Registers a new external SAML IdP using its Metadata XML.

* **Usage:** `./shyntr create-saml-connection [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--metadata-file` | **Yes** | - | Local file path to the SAML IdP's metadata XML file. |
| `--tenant-id` | No | `default` | The ID of the tenant this connection belongs to. |
| `--name` | No | `SAML IDP` | The descriptive name of the Identity Provider. |

### `get-saml-connection`

Retrieves details of a SAML Connection.

* **Usage:** `./shyntr get-saml-connection [id]`

### `delete-saml-connection`

Deletes a SAML Connection.

* **Usage:** `./shyntr delete-saml-connection [id]`

---

## 6. OIDC Connection (Identity Provider) Management

Manage external OpenID Connect Identity Providers (like Google, Azure AD) that Shyntr will trust.

### `create-oidc-connection`

Registers a new external OIDC Provider.

* **Usage:** `./shyntr create-oidc-connection [flags]`
* **Flags:**

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--issuer` | **Yes** | - | The exact Issuer URL of the external OIDC Provider (used for discovery). |
| `--client-id` | **Yes** | - | The Client ID provided by the external IdP. |
| `--client-secret` | **Yes** | - | The Client Secret provided by the external IdP. |
| `--tenant-id` | No | `default` | The ID of the tenant this connection belongs to. |
| `--name` | No | `OIDC Provider` | The descriptive name of the Identity Provider. |

### `get-oidc-connection`

Retrieves details of an OIDC Connection.

* **Usage:** `./shyntr get-oidc-connection [id]`

### `delete-oidc-connection`

Deletes an OIDC Connection.

* **Usage:** `./shyntr delete-oidc-connection [id]`