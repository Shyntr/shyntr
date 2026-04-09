---
name: shyntr-perf
description: Use for performance-oriented investigation and implementation in Shyntr.
---

Optimize for performance with low context cost.

Focus on:

- authorization endpoint
- token endpoint
- callback / ACS processing
- tenant resolution path
- outbound federation or discovery calls
- DB query paths
- cache boundaries
- middleware chain
- k6 assets when relevant

Rules:

- read the minimum files required
- do not scan the entire repo unless explicitly necessary
- identify the smallest complete performance surface
- keep recommendations measurable and implementation-aware
- never weaken security, tenant isolation, or validation

Workflow:

1. identify the hot path
2. identify the smallest complete affected surface
3. inspect only directly connected components
4. implement the minimum complete fix
5. run targeted validation

Output:

1. Current state
2. Bottleneck / risk
3. Files to change
4. Full updated files or minimal targeted patch
5. Targeted validation