# Contributing to Shyntr

Shyntr is a high-performance, open-source Identity and Access Management (IAM) platform written in **Go**.
It is designed to be protocol-agnostic, supporting OAuth2, OIDC, and SAML natively.

## 🚀 Getting Started

### Prerequisites

* **Go**: Version `1.23` or later.
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
