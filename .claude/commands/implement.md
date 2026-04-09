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

PRIMARY FAILURE RULE

When the task includes failing tests, runtime mismatches, or observed errors:

1. first classify each exact mismatch:
    - implementation wrong
    - test expectation wrong
    - fixture/setup wrong
2. resolve the exact failing mismatch first
3. only after the real mismatch is resolved, consider secondary hardening improvements
4. do not prioritize optional assertion strengthening before resolving the actual failure

CHANGE COMPLETENESS RULE
Before editing:

1. identify the exact bug or requested change
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

BOUNDED CHANGE PROPAGATION

Update all required files inside the smallest complete change surface, then stop.

Do:

- restore consistency across the affected path
- update sibling call sites if they are directly part of the same contract
- add or update the smallest deterministic test that proves the fix

Do not:

- stop after changing only one layer
- leave inconsistent call sites behind
- partially migrate a request or response contract
- scan unrelated packages
- refactor outside the affected surface

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