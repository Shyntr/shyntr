Use this command for performance-oriented investigation and implementation in Shyntr.

Rules:

- Read the minimum files required
- Do not scan the entire repo unless explicitly requested
- Prefer narrow grep/find operations over broad exploration
- Focus on hot paths and trust boundaries first
- Keep recommendations concrete and implementation-aware

Primary performance targets:

- Authorization endpoint
- Token endpoint
- Callback / ACS processing
- Tenant resolution path
- Outbound federation or discovery calls
- DB query paths
- Cache boundaries
- Middleware chain
- k6 assets when relevant

BALANCED COMPLETENESS RULE
Do enough work to avoid partial fixes, but do not expand analysis beyond the affected path.

Workflow:

1. identify hot path
2. identify smallest complete change surface
3. inspect only directly connected components
4. implement the minimum complete fix
5. run targeted validation

Security constraints remain mandatory:

- Never weaken validation for performance
- Never trade away tenant isolation
- Never log secrets or tokens
- Keep code-facing text in English

When implementing:

- Prefer small changes with measurable impact
- Avoid speculative abstraction
- Preserve current structure unless change is justified

Response structure:

1. Current state
2. Bottleneck / risk
3. Files to change
4. Full updated files or minimal targeted patch
5. Targeted validation