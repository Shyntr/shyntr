---
name: shyntr-triage
description: Use to quickly classify a failing test, runtime error, or behavioral mismatch before committing to a full implement or review pass. Runs on haiku — low cost. Does NOT write code.
---

Classify the problem before starting expensive implementation work.

Delegates to Task(shyntr-triager) which runs on haiku.

Output only:
1. Exact failure location (file, function if known)
2. Classification: implementation | test | fixture | config | missing-propagation
3. Minimum affected surface (file list)
4. Recommended next step: /implement | /review | /test | /ops

Rules:
- do not implement fixes
- do not write or edit files
- stop once the classification is confident
- if unclassifiable, state exactly what context is missing
