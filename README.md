<p align="center">
  <img src="assets/mascot.png" alt="Project Logo" width="175">
  <br>
  <i>Shyntr - Maneuvering Trust</i>
</p>

### The Protocol-Agnostic Authentication Hub

**Shyntr** is a lightweight, visionary Identity Broker designed to bridge the gap between modern applications and
diverse Identity Providers. It acts as a universal adapter, unblocking the complexity of authentication protocols so you
can focus on building your product.

Whether you need to expose your custom user database via standard OIDC or federate legacy SAML services with a modern
OAuth2 provider, Shyntr is the missing link.

---

## 🌐 The Vision

Identity management is fragmented. Developers are stuck building translation layers between legacy SAML systems, modern
OIDC clients, and custom backends.

**Shyntr unifies this chaos.** It does not manage users; it manages the *conversation* between your users and your
applications.

### ⚡ What Shyntr Does

* **The Authentication Hub:** Centralize your authentication traffic. Route requests from any application to any
  identity provider transparently.
* **Protocol Translation:** Seamlessly bridge the gap between **SAML** and **OpenID Connect/OAuth2**. Let your modern
  apps talk to legacy corporate directories, or let your legacy apps talk to modern social logins.
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

## 🎨 Bring Your Own UI (Headless Architecture)

Shyntr is **headless by design**. We don't force a generic login page on you.

* **You control the experience:** Build your Login, Consent, and Logout pages in your preferred technology (React, Vue,
  Go, etc.).
* **We handle the plumbing:** Shyntr redirects the user to your UI for verification and waits for a secure "Access
  Granted" signal to issue the tokens.

## 🏢 Multi-Tenancy Native

Built for SaaS from day one. Shyntr supports creating isolated tenants on the fly. A single instance can serve thousands
of different customers with distinct configurations, keys, and protocol requirements.

---

## 🛡️ Security & Compliance

Shyntr is built with a security-first mindset, adhering to strict OAuth2/OIDC standards:

* **OpenID Connect Core 1.0:** Full support for `prompt`, `max_age`, `auth_time`, and strict scope validation.
* **RP-Initiated Logout:** Secure session termination with `id_token_hint` and `post_logout_redirect_uri` validation.
* **Advanced Security:**
    * **RFC 7523:** Private Key JWT authentication for clients.
    * **Replay Protection:** JTI (JWT ID) tracking to prevent token reuse.
    * **Tenant Isolation:** Strict validation to prevent cross-tenant token usage.
    * **Grace Period:** Refresh Token Rotation with network-failure tolerance.

## 🔌 The Headless Flow (How it works)

Shyntr decouples the **Logic** from the **UI**. Here is the authentication flow:

1.  **Challenge:** When a user needs to login, Shyntr generates a `login_challenge` and redirects the user to your **External Login UI**.
2.  **Verification:** Your UI validates the user (username/password, MFA, etc.).
3.  **Accept:** Your UI calls Shyntr's Admin API (`PUT /admin/login/accept`) with the authenticated User ID.
4.  **Resume:** Shyntr verifies the handshake and issues the tokens (Access, Refresh, ID Token).

---

## Status

🚧 **Project is currently in active development.**
Shyntr is evolving into a production-ready Identity Broker. Follow the repository for updates on the roadmap and
protocol support.

---

## 🤝 Contributing

We love community! 💖

Found a bug? Have a great idea? Feel free to jump in! We appreciate every piece of feedback and contribution.
Let's build the ultimate Identity Broker together! 🚀

## 📄 License

Free as in freedom! 🦅

Shyntr is proudly open-source and licensed under the **Apache-2.0** license.
Check the [LICENSE](https://github.com/Shyntr/shyntr/blob/main/LICENSE) file for the boring legal details.

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

