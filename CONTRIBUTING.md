# Contributing to Shyntr

Shyntr is a high-performance, open-source Identity and Access Management (IAM) platform written in **Go**.
It is designed to be protocol-agnostic, supporting OAuth2, OIDC, and SAML natively.

## 🚀 Getting Started

### Prerequisites

* **Go**: Version `1.25.7` or later.
* **PostgreSQL**: Version `16` or later.

### Installation

1.  Clone the repository:
    ```bash
    git clone [https://github.com/Shyntr/shyntr.git](https://github.com/Shyntr/shyntr.git)
    cd shyntr
    ```

2.  Install dependencies:
    ```bash
    go mod tidy
    ```

3.  **Setup Database:**
    Make sure PostgreSQL is running. The default DSN is `postgres://postgres:postgres@localhost:5432/shyntr?sslmode=disable`.
    You can change this in `config/config.go` or via the `DSN` environment variable.

    Run the migrations to create the necessary tables:
    ```bash
    go run cmd/server/main.go migrate
    ```

4.  Run the server:
    ```bash
    go run cmd/server/main.go serve
    ```

## 🏗 Architecture

Shyntr follows a layered **Hexagonal / Ports & Adapters Architecture**:

* **`internal/domain/`**: Core domain models and contracts.
* **`internal/application/`**: Use cases, orchestration, security policies, and business rules.
* **`internal/adapters/`**: Infrastructure implementations such as HTTP handlers, persistence, IAM integrations, and audit logging.

## 🤝 Guidelines

1.  All code and comments must be in **English**.
2.  Do not use any external branding (other than strictly required library imports).
3.  Keep the core logic independent of specific frameworks where possible.

### Database Constraints & Persistence
* **Composite Primary Keys:** The `o_auth2_sessions` table strictly uses a composite primary key (`signature`, `type`). Never attempt to query or delete a session by `signature` alone, as this will cause cross-token-type data leaks.
* **Refresh Token Uniqueness:** A partial unique index enforces that only one active refresh token can exist per `request_id` to prevent token cloning.

### Testing Discipline
Shyntr enforces strict testing standards for security boundaries:
* **No Mock Strings for Tokens:** When writing tests for protected endpoints (like `/userinfo`), you cannot use dummy strings (e.g., `"fake-token-123"`). You must instantiate the `compose.NewOAuth2JWTStrategy`, generate a cryptographically valid JWT Access Token with proper claims, and pass it in the `Authorization` header.
* **Asserting Zero Trust:** Always write negative assertions (e.g., verifying that data *does not* leak when a scope is missing).

### Outbound Security Testing

Any feature that performs outbound HTTP communication must be validated through policy enforcement.

Tests must include:

* Allowed outbound request scenarios
* Blocked requests (private IP, loopback, invalid scheme)
* Failure cases (DNS resolution failure, timeout)

Direct outbound HTTP calls without policy validation are not allowed.

Tests must also validate:

* Global outbound policy fallback when no tenant policy exists
* Policy precedence (tenant policy overrides global policy)
* Enforcement consistency across all outbound targets (JWKS, Webhooks, Discovery)

Failing to test fallback behavior is considered a security gap.