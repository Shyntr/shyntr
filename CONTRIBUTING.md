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
    git clone [https://github.com/nevzatcirak/shyntr.git](https://github.com/nevzatcirak/shyntr.git)
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

Shyntr follows a **Hexagonal Architecture**:

* **`internal/core/`**: Contains the pure business logic (Auth provider, SAML service).
* **`internal/data/`**: Handles database interactions (GORM models, repositories).
* **`internal/api/`**: Manages HTTP requests (Gin handlers).

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