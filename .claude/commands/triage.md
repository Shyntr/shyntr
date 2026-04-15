Use this command to quickly classify a failing test, runtime error, or behavioral mismatch in Shyntr
BEFORE starting a full implement or review pass. This keeps expensive sonnet calls bounded.

Preferred approach: delegate to Task(shyntr-triager) — it runs on haiku and is optimized for
narrow classification without writing code.

Rules:
- Do not implement fixes in this pass
- Do not explore beyond the minimum needed to classify the failure
- If the problem is clear, output the classification immediately

Output:
1. Exact failure location (file, function if known)
2. Classification: implementation | test | fixture | config | missing-propagation
3. Minimum affected surface (file list)
4. Recommended next step: /implement | /review | /test | /ops

If unclassifiable: state exactly what context is missing before proceeding.
