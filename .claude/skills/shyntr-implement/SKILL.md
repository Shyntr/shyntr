---
name: shyntr-implement
description: Use for production-ready code edits, migrations, and narrow patches in Shyntr.
---

Implement code changes inside Shyntr.

Core behavior:

- Follow snapshot paths exactly if a snapshot exists
- Preserve naming, packages, layers, and constructor patterns
- Prefer minimal, compatible changes
- Do not invent helpers or abstractions unless necessary
- Keep all code-facing text in English
- Never log secrets, tokens, passwords, private keys, or raw assertions

Security constraints:

- Secure by default
- Enforce tenant isolation
- Token endpoint is a trust boundary
- Exact redirect URI matching is mandatory
- PKCE is required for public clients

Primary failure rule:

1. classify the exact mismatch first:
    - implementation wrong
    - test expectation wrong
    - fixture/setup wrong
2. resolve the real mismatch first
3. only then consider secondary hardening

Complete-change workflow:

1. identify the exact bug or requested change
2. identify the smallest complete affected surface
3. update all required files inside that surface
4. stop once consistency is restored

Minimum surface checklist:
- endpoint or handler
- service or usecase
- repository or store
- validation
- DTO or mapping
- wiring or route registration

- config if contract changed
    - tests

Do not:

- fix only the first file you see
- leave sibling call sites inconsistent
- partially migrate contracts
- scan unrelated packages

When modifying code:

- Return FULL file content
- Include FILE PATH above each file

Response structure:

1. Current state
2. Problem / risk
3. Files to change
4. Full updated files
5. Targeted validation