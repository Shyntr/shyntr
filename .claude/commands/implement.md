Use this command when the task is to change code, edit files, add migrations, or produce a narrow production-ready patch
in Shyntr.

Rules:

- Follow the snapshot strictly if one exists
- Use exact file paths from the snapshot
- Preserve naming, packages, layers, and constructor patterns
- Prefer minimal, compatible changes
- Do not invent helpers or abstractions unless necessary
- Do not broaden scope without reason

Security rules:

- Secure by default
- Enforce tenant isolation
- Prefer short-lived credentials
- Never log secrets, tokens, passwords, private keys, or raw assertions
- All code-facing text MUST be in English

OAuth2 / OIDC / Fosite rules:

- Token endpoint = trust boundary
- Enforce exact redirect URI matching
- PKCE REQUIRED for public clients
- Explicit tenant isolation in all flows
- Do NOT assume helper utilities unless visible in the snapshot
- Use Fosite-compatible patterns for secrets and validation

CHANGE COMPLETENESS RULE
Before editing:

1. identify the exact bug or change target
2. identify the smallest complete change surface
3. list every directly affected file inside that surface

Minimum propagation checklist:

- entry handler / endpoint
- service or usecase
- repository or store
- validators
- DTO / mapping
- routing or wiring
- config if contract changed
- tests protecting the changed behavior

Do not:

- stop after changing only one layer
- leave inconsistent call sites
- partially migrate a request or response contract
- change unrelated modules

Validation rule:

- run the smallest targeted validation that proves the change works
- expand validation only if the first result indicates wider impact

When modifying code:

- Return FULL file content
- Include FILE PATH above each file
- Keep formatting clean and copy-paste ready

Response structure:

1. Current state
2. Problem / risk
3. Files to change
4. Full updated files
5. Targeted validation