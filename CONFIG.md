# Configuration Guide

Shyntr follows the **12-Factor App** methodology. All configurations are managed via Environment Variables. This document describes all available variables, their default values, and their purposes.

## 1. Core Server Settings

| Environment Variable | Default Value | Description                                                                                                                                                                                                                    |
| :--- | :--- |:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PORT` | `7496` | The port number on which the **Public API** (SAML/OIDC endpoints) runs.                                                                                                                                                        |
| `ADMIN_PORT` | `7497` | The port number on which the **Management/Admin API** (Dashboard and Auth Portal internal communication) runs.                                                                                                                 |
| `ISSUER_URL` | `http://localhost:7496` | The authoritative base URL of the Identity Hub. **CRITICAL:** This value is embedded into the `iss` claim of all JWT Access and ID Tokens. Downstream resource servers will reject tokens if this does not match exactly, and as the base for SAML metadata endpoints. |
| `LOG_LEVEL` | `info` | Defines the verbosity of the logger. Valid values: `debug`, `info`, `warn`, `error`, `fatal`.                                                                                                                                  |
| `GO_ENV` | `development` | Setting this to `production` switches the logger output to JSON format and disables human-readable console colors.                                                                                                             |
| `GIN_MODE` | `debug` | Set to `release` in production to disable Gin framework's route debugging output and optimize routing performance.                                                                                                             |

## 2. Database Configuration

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DSN` (or `DATABASE_URL`) | `postgres://shyntr:secretpassword@localhost:5432/shyntr?sslmode=disable` | The PostgreSQL connection string. |
| `DB_MAX_IDLE_CONNS` | `10` | The maximum number of connections in the idle connection pool. |
| `DB_MAX_OPEN_CONNS` | `100` | The maximum number of open connections to the database. |

## 3. Cryptography & Security

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `APP_SECRET` | `12345678901234567890123456789012` | A strict **32-byte** string used for AES-256-GCM encryption. It encrypts sensitive data in the database (like Client Secrets and Private Keys) and signs session states. |
| `APP_PRIVATE_KEY_BASE64` | `""` (Empty) | Base64 encoded RSA Private Key (PKCS#1 or PKCS#8 format). If left empty, Shyntr will auto-generate a secure RSA key pair and store it encrypted in the database. |
| `COOKIE_SECURE` | `false` | Set to `true` in production to enforce `Secure` flag on HTTP cookies (requires HTTPS). |
| `SKIP_TLS_VERIFY` | `false` | If `true`, ignores SSL/TLS certificate errors on outbound HTTP requests (e.g., OIDC Discovery). **Use only in development!**  |

## 4. Headless UI Routing (Auth Portal)

These URLs tell Shyntr where your custom front-end application (Auth Portal) is hosted.

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `EXTERNAL_LOGIN_URL` | `http://localhost:3000/login` | The URL Shyntr redirects users to when authentication is required. |
| `EXTERNAL_CONSENT_URL` | `http://localhost:3000/consent` | The URL Shyntr redirects users to when OAuth2/OIDC scope consent is required. |

## 5. Token Lifespans

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ACCESS_TOKEN_LIFESPAN` | `1h` | Global default lifespan for Access Tokens (e.g., `15m`, `1h`). |
| `ID_TOKEN_LIFESPAN` | `1h` | Global default lifespan for OIDC ID Tokens. |
| `REFRESH_TOKEN_LIFESPAN`| `720h` (30 Days) | Global default lifespan for Refresh Tokens. |

> **Security Note:** Access Tokens are stateless JWTs. To minimize the risk window of compromised tokens in a Zero Trust architecture, keep `ACCESS_TOKEN_LIFESPAN` short (e.g., `15m` to `1h`) and rely on Opaque Refresh Tokens for session continuation.

## 6. Cross-Origin Resource Sharing (CORS)

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:3274` | Comma-separated list of origins allowed to call the **Public API**. |
| `ADMIN_CORS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:3274,http://localhost:7497` | Comma-separated list of origins allowed to call the **Admin API**. |

## 7. Multi-Tenancy

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DEFAULT_TENANT_ID` | `default` | The ID of the root tenant created upon initial database migration. All global connections and clients belong here. |