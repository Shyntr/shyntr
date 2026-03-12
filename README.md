<p align="center">
  <img src="assets/mascot.png" alt="Project Logo" width="175">
  <br>
  <i>Shyntr - Maneuvering Trust</i>
</p>

### The Protocol-Agnostic Authentication Hub

**Shyntr** is a lightweight, visionary Identity Broker designed to bridge the gap between modern applications and
diverse Identity Providers. It acts as a universal adapter, unblocking the complexity of authentication protocols so you
can focus on building your product. Whether you need to expose your custom user database via standard OIDC or federate
legacy SAML services with a modern OAuth2 provider, Shyntr is the missing link.

---
## 🛡️ Zero Trust & Token Architecture

Shyntr implements a rigorous, high-assurance token architecture designed for Zero Trust environments:

* **JWT Access Tokens (RFC 9068):** Access tokens are issued as stateless JSON Web Tokens. They include strict claims (`iss`, `sub`, `aud`, `client_id`, `amr`) allowing your downstream microservices to authorize requests independently and securely.
* **Opaque Refresh Tokens:** To prevent replay attacks and ensure immediate revocation capabilities, refresh tokens are strictly opaque (stateful).
* **Token Rotation & Grace Period:** Every use of a refresh token rotates the token family. A strict 15-second grace period is enforced to handle network latency while neutralizing token cloning attempts.
* **Strict OIDC Enforcement:** Exact redirect URI matching, PKCE enforcement for public clients, and explicit response mode whitelisting are mandatory.

---

## 🚀 Quickstart

The fastest way to experience Shyntr is using our official `quickstart/docker-compose.local.yml`. It spins up the complete ecosystem: the
core database, the Identity Hub backend, the management Dashboard, and the user-facing Auth Portal.

Create a `docker-compose.yml` file with the following content:

```yaml
services:
  # ----------------------------------------
  # 1. DATABASE (PostgreSQL)
  # ----------------------------------------
  postgres:
    image: postgres:16-alpine
    container_name: shyntr_db
    environment:
      - POSTGRES_USER=shyntr
      - POSTGRES_PASSWORD=secretpassword
      - POSTGRES_DB=shyntr
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: [ "CMD-SHELL", "pg_isready -U shyntr" ]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - shyntr-net

  # ----------------------------------------
  # 2. SHYNTR IDENTITY HUB (Backend)
  # ----------------------------------------
  shyntr-backend:
    image: shyntr/shyntr:1.0.0-beta.7
    container_name: shyntr_app
    ports:
      - "7496:7496" # Public Port (SHYN)
      - "7497:7497" # Admin Port (ADMN)
    environment:
      - GIN_MODE=release
      - GO_ENV=production
      - DSN=postgres://shyntr:secretpassword@postgres:5432/shyntr?sslmode=disable
      - APP_SECRET=12345678901234567890123456789012
      - PORT=7496
      - ADMIN_PORT=7497
      - ISSUER_URL=http://localhost:7496
      - APP_PRIVATE_KEY_BASE64=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUpRZ0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQ1N3d2dna29BZ0VBQW9JQ0FRREhERFR5NlQvQ2dINksKUHY1Z3FBUlRUZ2szU3B5V2JBOTllNU5DamZYb3EvY3ZWR1V2dkkxSmsvU1NwNUk5V3pwY0pvQ2RJWGZteHhOUworc2dhNG1uTCtGTVpYdGhwTnlwOElwS1dhNE5vblN5K3RESVhuTndGZlA4SUU3eGZjb0g3NVpaMTMvNjVyVWUvCnhDVzVmUWNPZ0EyWTNXRStuVW5OVjRKVm9tdmM5NGZHUmpQTHlwMGI1SHZTYkZjZzRxbitZQ0JnVUpXbUtjaW0KangwK3RsTG5UdXFHU3daZEpKMmk5ZDlKa0xBNmpZOWcvZWZxeENjZWs5OFJaOUhiOGZqYVYzYnY2WkRWZHJzRApXVUdyc0tCWHdjSVF3MGphbC9wZ1E5WkoycG1aTGdtcFNNbWF1M2lFOWI4UUora3Q5bXRlemFlQlE1S2krbm9VCmt6SkpiSDZCYzd1MllaM3hqdzZ3SDA5WCtSUnMveVJJSFkxaEtGNjJ2TFIzWHlRVEVlRWdrVW1yR0ZjdlZzY1YKaDV4SkJSWFBLczF1QnNuWkxabGV2VXRUUHJmMGV4ZTZxYXRMcUNKZXV5T1lHSEpvNHlMWHJIdkpoQWluRFFiYQo5VFlLeUxaQTBWUnUzN29KODh0UmxnUlQ3SWt6elJuZTE2VmdFRElidGswdTg0OWhvV3VSc0t5ajJlYUlSS2xQCk44cWQ2M0lxQkhGVXVEeThBWFRkVTNvRFh0ZEJJVlpYSmRlc2ZxQWtqMUZNS3R3QTRRcVZndHRLMUVFWE9tYkIKV3BmZ0VIcitCa3BaWW54MHBhL1BZRVU2MW9CZ0xpZWRaOTdjVlJlVXlsZVRtUzY0d0ZFb3RpVEtHS3pOaHlBOQppcG5HbjRJWU9OZUdkazhPZVA2R2ZrOGpEU0wydFFJREFRQUJBb0lDQUIydVM4ejNEQXRvVnJZdHE0ZmxOZlBvCkhJYXlxUVBqTERJbGRiR0VjcWxWenordkFZR3JSNVF6ckZJY0M3bjdld25Yc2ZEOFZ5RkNDVGNqN3lmWElEaUsKbUhXZGgzNjArN0JVQlhESnFtZzBtOEg2SThnU20xcDBKNkZnTkFRMWtuMXA0RlJHYVBqdUJsZHBtOGg3aE14YwpPdXJUQkJldW81MHJrZU5NRzNKeE5MMVRwWkNiYjI4RDFKVHRrOVp6Qmk5SXpUc2ZlUmswZk5lZFdwcUozSFhpCmRpVTlWYjhZNFNxMktDd1RsN3U3ZFNoYzVETEZPaUljb2JRNk8zaGxMaHI4MU43MGdLVGNGZ25yU3RnYnQrVXUKSHM2YUdDaUVaaERwdksvNW1WTFdveGtyb2VoaFVSamVmaldlQmU3VkluQ2FFUUs4L1VZeFBIZ0o5UU11MnZRVwpTS1c5RExJLzBzL3lCZytqV25sSnZlT1A2Z0pLSEZ5aU16dDhGc0FWa3FES1kxaDFxR05RcEgxSkVNeXc5QW1LCjBwTkxLc3FUOWIrTGI5TUFpWFgwL1plNDZaQWcwSjludlNCczlWaU1HMkc4R092c2ZoVEVEcGtGeUVYM1FjS04KUWFKV3B2eEE5M1ZJZkNzWDdZTlM1YjhFZEhwa2RqQUE0RkRldmliMEc1T05lNTBvdUlaTEtxS1FXR2Z6NHZuegorVVN1eVpCZUhTNHNtK25lYWQ3OXZPQUxVNW9qcjVvRHJna24wem5FaUQ2UTkraFNHc0RnVGpreDdicVpmaEhKClROdkR4MzcvSTAvWk9CTzlwUlU5M0l1Q21TaFpLa0VhdjdwVmdvMEtTaUF5TnpzS0lxUE94enMxVzhRT0FiTmMKWVhCa2ZIRURHS0JpSFk5cUpMMFJBb0lCQVFEdnlLL0xGY0NjVyt5TFY2V1AvMjNUQlJQcHlmdE5hNy96ckdCUApMN0l2NkJYbnJ4OS9rZGEreGh6RkhYMGVyOFRLdlFQcWZyUnlaaFMrWjJ6Y1g3S2NlWFBESlN3T3dnWU5xOGliCnBNLzh0ZnBmbDNaWmdPYXg2bnoxRmw1L1RadnlyMkp0b09EUTBhSElIdGNsd3VDdG40SGRlTmlCVEZyUEZqMGgKdU1QSWZuVmxrZ0xEaWU2aGVDZU9yYlR5bkNuOFpaeXNZNFNBMmVncFArMmNCYzZ1Q3UzZmZ3ekE5bE9WNnBvUgpYaHVTemhiQWdzVEkwYmtvRDNCTTJSdERkNXp0TGUxYkZOWUZ1NHNhVGszNnBJLzJDUlpZdXZnbkJZamU5aWxiCndQZVRXNW10MHlNZzJmMmVRL2dHS1hicDZYOWY0V2htb2YzTGxaNzEwc2I2NVZqNUFvSUJBUURVZ2tQQUcxQWUKNXdFNHJLcmVSNkU5dUk5b21VR2ZoUU5lN2FxbnNFT3hJMU5VWmRSMThvV083cGplTlZseGQ0b2ZubldETTc1NwpXaTFFVnRLOXB0aG43RThqbEVnQ2RISXUyVmpLbVJaYWtSK3h6c2MwRU1NNGduQUtIM0dldjlEcTg3TVNHRDhOCkFTVmk1bnNWbFJ2bmUzYzFES3FJQ0RPK25abWhJN1RHYmx0djZ3Y0lneWtFR3hlR1B6U3laWmp6bnNkb3BDY2cKRHhCUE9mUmcrRSt2ZTdqbnZGT2lVbEVKOUtmcHVmLzZ2SU1nMlRES0k4RGE1UXpCd0xHRHlvTi9MZ1lpMmU1Ngp6TnJ3UkRSUXlmYTZqZlNZQW5yVEVDUHFOTU1HWVlVUFlTOW9ob2tBM3BhMmYyaEFOa2JJVWNyNHFldFpDc3RaClNucDF2bm83QmhhZEFvSUJBRVJHcTYrekdPNHN5cFQrdHZqaXJYM3BzenJkdFgzZEVZSXI4aHg2STAyNjB3bnUKZHBTWGpVTXpIQndRZ29FTFlZaXMrNEY0NUo2eWJIT3U5WE5tbUhBdnNRTy9BT1dPMzdSaTFyTmk0WW8rc3ZVbgpKcDdqc2t5MHpUSG9WYTRBQmtpN0lkYS9lV1JjWEtta0JuVU5JWGF1dFlhL2t6NTE1R0dWSG9FTW9FcmxuejMxCnJtM0pSN2FZaFFMK2VVaWZxT0RpZWhNb0h5R2xhcExjVGljZ0RETElqK1VVd3lmcXUvQXpKZjJPQTJIdzVzK1kKTExwVjVWZi8xV1U4YUtQMFdpMjY1eHdKT2N2V0ZBekFnVG0rUS9PMXNMUkJRTW16ckw1MzcxemQvR0RzTXowbwpvcGNIRzAxR1kwZzE1Rk5FbG0xUnZLMkVzTVNZYlBQb09acFZWZGtDZ2dFQVpualNGcWFWQWZHK2d3ZXY5VE54Ckt3UCtFeUFqcHJwTEg5RlhBemxaeXVjUDNaaWsxS00zaCs3QnhCVFJwb2RRRVdNbG96aW1WM0RxZHhPdTEwakcKL1lYVHU0SmJIdVByMDI5M0EyckNmcldRSlB0aXoxWnQ3S2ZwUXRoYXY0UWJSOUJ2dnYvMkYxMUFHK3FyMjRKbApURUFiQVhlMEc1aG82emV2eHlZaW03VEhYclprVTlSN1NNR1BuR3FLREtRMUZ2U3ZqMlBvZ2VzQm9GSi81dXFWCjhqYWt1UW4xQWtiVFVRdXFsR2ZlYVpmUlcxdWZ6VGxrVzZrcmQ1cGxmdmwrWXl0Y1JoMzBnejZaTEZhWEs0WFgKOWFsU0VxTFBlMHRESmtKKzhHckI4T0thSzdzRUFXbFVIM2hjV3VwUlEzTTlmcDdoSDdTMnpiMitRMXl3TUJvRgplUUtDQVFFQTVHdUhpRGwzOHc2Vnp4UXRxN1crbmdhVDRDVzVIYkQyNHZKTXFHUEhVZXRjWU0zQnpmcUtwbWFsCnBYRFNPYVNsSGc1c1hzamNRTXJrTFlGdW1IU1JhUUFjamZHYUd6c0hFYm1EWWMyZWtLZ2FPdHdha1grUVA0Z1EKQ0xwbXVEZk5RM0I2cXJKVnRyQkwyRS9jamYzZjROdUhmMEExWHlrcDcvTEdkcjdwMlVXQ2Q3Zjk2MDE1UE8wMgpqMkhka1JRanZwcmZrTzBkWFZHTlJKckFGZUlKZTN2dmtsMlRHTkhTTUNkVVVQMHVoT3EwUXRrVEFKbDV1eitZClhBMkpLWXNZekFCeFhXRVBCUlE3WDFBWUVXV1B2QTB0RFVkaTQ4bGtjMnB1L2dVODgra3ZaNGIwTXB4QU5qNHMKR0Z3MllMMkEyQ240ZEw2TWxFUUR3STFkeFBpdmZ3PT0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=

      - EXTERNAL_LOGIN_URL=http://localhost:3000/login
      - EXTERNAL_CONSENT_URL=http://localhost:3000/consent

      - CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3274
      - ADMIN_CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3274,http://localhost:7497
      - LOG_LEVEL=info
      - SKIP_TLS_VERIFY=true #Development only
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - shyntr-net
    healthcheck:
      test: [ "CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:7496/health" ]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s
    command: >
      sh -c "./shyntr migrate && ./shyntr serve"

  # ----------------------------------------
  # 3. SHYNTR DASHBOARD (React / Nginx)
  # ----------------------------------------
  shyntr-dashboard:
    image: shyntr/shyntr-dashboard:1.0.0-beta.2
    container_name: shyntr_dashboard
    ports:
      - "3274:80"
    environment:
      - REACT_MANAGEMENT_BACKEND_URL=http://localhost:7497
      - REACT_PUBLIC_BACKEND_URL=http://localhost:7496
    depends_on:
      shyntr-backend:
        condition: service_healthy
    networks:
      - shyntr-net

  # ----------------------------------------
  # 4. SHYNTR AUTH PORTAL (Next.js)
  # ----------------------------------------
  shyntr-auth-portal:
    image: shyntr/shyntr-auth-portal:1.0.0-beta.3
    container_name: shyntr_auth_portal
    ports:
      - "3000:3000"
    environment:
      - SHYNTR_INTERNAL_API_URL=http://shyntr-backend:7496
      - NEXT_PUBLIC_BACKEND_URL=http://localhost:7496
    depends_on:
      shyntr-backend:
        condition: service_healthy
    networks:
      - shyntr-net

# ----------------------------------------
# VOLUMES & NETWORKS
# ----------------------------------------
volumes:
  postgres_data:

networks:
  shyntr-net:
    driver: bridge

```

Run the stack in detached mode:

```bash
docker-compose up -d

```

* **Dashboard:** http://localhost:3274 (Manage Tenants and Identity Providers)
* **Auth Portal:** http://localhost:3000 (User-facing Login and Consent screens)
* **OIDC Discovery:** http://localhost:7496/.well-known/openid-configuration

---

## 🧩 The Shyntr Ecosystem

Shyntr is **headless by design**, meaning the core backend strictly handles cryptographic protocols, token generation,
and security boundaries. It does not enforce a generic UI.

However, to provide a complete out-of-the-box experience, the ecosystem includes two optional, reference
implementations:

1. **Shyntr Identity Hub (Core Backend):** The high-performance Go application that acts as the universal protocol
translator and Zero Trust Broker.
2. **Shyntr Auth Portal (Next.js):** A user-facing authentication interface. It handles the Login, User Consent, and
   Logout routing. **You can use this directly, or build your own custom login UI in any language.**
3. **Shyntr Dashboard (React):** A central management interface. It provides an intuitive, enterprise-grade admin portal
   to manage Tenants, OIDC/SAML Connections, and advanced Attribute Mapping rules. **You can use this directly, or
   manage the backend entirely via CLI/API.**

---

## 🌐 The Vision

Identity management is fragmented. Developers are stuck building translation layers between legacy SAML systems, modern
OIDC clients, and custom backends. **Shyntr unifies this chaos.** It does not manage users; it manages the
*conversation* between your users and your applications.

### ⚡ What Shyntr Does

* **The Authentication Hub:** Centralize your authentication traffic. Route requests from any application to any
  identity provider transparently.

* **Protocol Translation:** Seamlessly bridge the gap between **SAML** and **OpenID Connect/OAuth2**. Let your modern apps
talk to legacy corporate directories, or let your legacy apps talk to modern social logins.

* **Rapid Compliance:** Instantly provide standard-compliant OIDC endpoints for your custom internal systems without
rewriting your security layer.

## 🚀 Core Scenarios

### 1. The Gateway (Federation)

*You have an existing OpenID Connect service (like Auth0, Google, or a custom OIDC Provider), but you need to support
SAML enterprise customers.*

Shyntr sits in the middle. It accepts the SAML request, translates the handshake, validates the session against your
existing OpenID provider, and routes the authenticated user back—all without your Identity Provider needing to know a
thing about SAML.

### 2. The Interface (Custom Provider)

*You have a proprietary user database and need to expose it to 3rd party apps via standard OAuth2/OIDC.*

Instead of building an OAuth2 engine from scratch, connect Shyntr to your system. Shyntr handles the cryptographic heavy
lifting, token generation, and protocol flow, while your system simply approves the login.

## 🏢 Multi-Tenancy Native

Built for SaaS from day one. Shyntr supports creating isolated tenants on the fly. A single instance can serve thousands
of different customers with distinct configurations, keys, and protocol requirements.

---

## 🛡️ Security, Compliance & Observability

Shyntr is built with a security-first mindset, adhering to strict industry standards:

* **OpenID Connect Core 1.0:** Full support for `prompt`, `max_age`, `auth_time`, and strict scope validation.

* **RP-Initiated Logout:** Secure session termination with `id_token_hint` and `post_logout_redirect_uri` validation.

* **Advanced Security:**
  * **RFC 7523:** Private Key JWT authentication for clients.

  * **Replay Protection:** JTI (JWT ID) and SAML Message ID tracking to prevent token reuse.

  * **Tenant Isolation:** Strict validation to prevent cross-tenant data leakage.

  * **Grace Period:** Refresh Token Rotation with network-failure tolerance.

* **Enterprise Observability:**
  * **W3C Trace Context:** Native OpenTelemetry (OTel) integration for distributed tracing across microservices.
  * **RFC 9457:** Standardized Problem Details for HTTP APIs, ensuring predictable and secure error handling on management
    endpoints.

## 🔌 The Headless Flow (How it works)

Shyntr decouples the **Logic** from the **UI**. Here is the authentication flow:

1. **Challenge:** When a user needs to login, Shyntr generates a `login_challenge` and redirects the user to your *
*External Login UI** (e.g., the Shyntr Auth Portal).

2. **Verification:** Your UI validates the user (username/password, MFA, SAML/OIDC SSO, etc.).

3. **Accept:** Your UI calls Shyntr's Admin API (`PUT /admin/login/accept`) with the authenticated User ID and context
claims.

4. **Resume:** Shyntr verifies the handshake and issues the tokens (Access, Refresh, ID Token).



---

## 📚 Documentation

To get the most out of Shyntr, please refer to our detailed guides:

* **[Configuration Guide (CONFIG.md)](https://www.google.com/search?q=./CONFIG.md)**: Learn about all environment
  variables, database settings, and tuning parameters required to run Shyntr in production.
* **[CLI Reference Guide (CLI.md)](https://www.google.com/search?q=./CLI.md)**: Discover how to manage tenants,
  OIDC/SAML clients, and identity providers directly from the terminal without needing direct database access.

---

## 🤝 Contributing

We love community! 💖
Found a bug? Have a great idea? Feel free to jump in! We appreciate every piece of feedback and contribution.

## 📄 License

Shyntr is proudly open-source and licensed under the **Apache-2.0** license. Check the `LICENSE` file for details.

---

<div>
  <a href="https://buymeacoffee.com/nevzatcirak17" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="40" align="left">
  </a>
  <a href="https://nevzatcirak.com" target="_blank">
    <img src="assets/nev.svg" alt="NEV Logo" height="40" align="right">
  </a>
</div>
<br clear="all">