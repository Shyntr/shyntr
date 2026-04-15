# Shyntr Codex Guide

This file is the primary Codex instruction source for the whole repository.
Keep answers and exploration bounded. Read the minimum surface needed for the task.

## Project Snapshot

- Language: Go
- Entry point: `cmd/server/main.go`
- Architecture: onion-style `internal/domain` -> `internal/application` -> `internal/adapters`
- Core product: multi-tenant identity router / broker for OAuth2, OIDC, SAML, external login-consent UI

## Read Order

Use this order unless the task clearly points elsewhere:

1. `README.md`
2. `AGENTS.md`
3. `config/config.go` for env contract and defaults
4. Target package only
5. `cmd/server/main.go` only for startup, wiring, CLI, or route registration changes

Avoid loading large generated files unless the task requires them:

- `docs/swagger.json`
- `docs/swagger.yaml`

## Code Map

- `internal/domain/model`: framework-free domain models and invariants
- `internal/application/usecase`: business rules and orchestration
- `internal/application/security`: auth, token, and security helpers
- `internal/adapters/http`: handlers, middleware, router setup
- `internal/adapters/persistence`: GORM models and repositories
- `pkg/logger`, `pkg/utils`, `pkg/tenant`: shared infra helpers
- `config/config.go`: env-backed runtime configuration
- `quickstart/`: local deployment examples
- `k6/`: performance assets

## Non-Negotiable Boundaries

- Preserve strict tenant isolation in every auth and management path
- Treat token endpoint, login challenge, consent challenge, callback, and ACS as trust boundaries
- Never log or print secrets, tokens, passwords, private keys, raw SAML assertions, or raw external credentials
- Keep code-facing text in English
- Prefer minimal compatible changes over broad refactors

## Working Rules

- Use `rg` and targeted reads; do not scan the entire repo for narrow tasks
- Reuse existing constructors, repository patterns, handlers, and tests before creating new helpers
- When behavior changes, check the smallest complete surface:
  handler -> usecase -> repository -> config -> tests
- Prefer targeted validation first:
  - package test
  - focused `-run` test
  - full suite only for cross-cutting auth changes
- If the task is exploratory, summarize first and do not edit until the direction is clear

## Cost Control

- Default to narrow prompts with exact file paths, boundary, and expected output
- For bug work, start with `triage` before broad implementation
- For review work, inspect only the directly affected boundary first
- Ask for summary-first responses when you do not need a patch yet
- Do not restate repo-wide architecture unless the user asked for it

## Prompt Patterns

Use short, mode-first prompts:

- `triage: classify failing PKCE flow in internal/adapters/http/handlers/oauth2.go`
- `implement: add regression test for tenant isolation in ...`
- `review: inspect SAML callback trust boundary in ...`
- `explain: summarize auth request lifecycle using these files only ...`

## Useful Commands

- `go test ./internal/... -count=1`
- `go test ./internal/adapters/http/handlers/... -run TestName -count=1`
- `go test ./internal/application/... -run TestName -count=1`
- `go test ./... -count=1`
- `go build ./cmd/server`

## Existing AI Assets

- `.claude/` contains richer task modes and command docs; consult only if the task benefits
- `docs/chatgpt-project-instructions.md` is historical reference; prefer this file for Codex behavior
