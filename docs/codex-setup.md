# Codex Setup For Shyntr

This repository now includes a Codex-first instruction layer in `AGENTS.md`.

## What To Use

- `AGENTS.md`: primary project instruction file for Codex
- `.codex/config.toml`: repository-local source template for Shyntr Codex settings
- `.codex/config.toml.example`: copy-friendly example version of the same settings
- `.claude/`: secondary reference only when a task needs deeper mode-specific guidance

## Why This Structure

Shyntr is a security-sensitive Go codebase with:

- one large Cobra entry point in `cmd/server/main.go`
- onion-style separation across `domain`, `application`, and `adapters`
- strict multi-tenant and auth-flow trust boundaries
- large generated API docs that are expensive to load unnecessarily

The cheapest reliable Codex setup is:

1. keep the auto-loaded project doc short
2. push deeper guidance into normal repo docs
3. use profile-based model selection instead of one heavy default

## Recommended Global Config

Use `.codex/config.toml` as the project source of truth, then copy or merge the relevant parts into `~/.codex/config.toml`.

Versioning policy:

- commit `AGENTS.md`
- commit `.codex/config.toml`
- optionally commit `.codex/config.toml.example`
- never commit `~/.codex/config.toml`
- keep machine-specific or temporary Codex variants as `.codex/*.local.toml`

Recommended profiles:

- `shyntr_fast`: default exploration, summaries, narrow edits
- `shyntr_build`: implementation that spans a few files
- `shyntr_deep`: security review, architecture, cross-cutting auth changes

## Suggested Usage

Default interactive session:

```bash
codex -C /Users/nevzatcirak/Developer/projects/shyntr -p shyntr_fast
```

Narrow implementation:

```bash
codex -C /Users/nevzatcirak/Developer/projects/shyntr -p shyntr_build "implement: add regression test for tenant isolation in internal/adapters/http/handlers/oauth2.go"
```

Deeper security review:

```bash
codex -C /Users/nevzatcirak/Developer/projects/shyntr -p shyntr_deep "review: inspect token endpoint and callback tenant boundaries using only the directly affected files"
```

## Cost-Effective Prompting Rules

- Start with a mode word: `triage`, `implement`, `review`, `explain`, `ops`
- Include exact file paths whenever possible
- Ask for `summary first` before asking for a patch on broad topics
- Say `use only the directly affected files` for narrow tasks
- For bug work, ask Codex to classify first, then patch

## Repo-Specific Notes

- Prefer `config/config.go` when the task mentions env, ports, token lifetimes, login URL, or consent URL
- Avoid loading `docs/swagger.json` and `docs/swagger.yaml` unless the task is about generated API contracts
- Use targeted `go test` commands before the full suite
