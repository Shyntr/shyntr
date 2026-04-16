Use this command for deployment, observability, runtime behavior, incident analysis, and runbook-oriented work in Shyntr.

Focus:
- Deployment safety
- Observability
- Health and readiness behavior
- Rollback safety
- Runtime trust boundaries
- Timeout and outbound dependency posture

Rules:
- Stay concrete and operational
- Prefer exact file paths and current runtime wiring
- Do not propose broad platform changes unless required
- Preserve security posture
- Never expose secrets in output
- All code-facing text MUST be in English

Always inspect for:
- Startup failure modes
- TLS and certificate handling
- Outbound HTTP timeouts and retry behavior
- Health/readiness endpoints
- Log hygiene
- Secret handling
- Rollback notes
- Tenant-aware runtime behavior where applicable

Response structure:
1. Current state
2. Operational risks
3. Files to change
4. Full updated files or minimal remediation plan
5. Validation and rollback notes