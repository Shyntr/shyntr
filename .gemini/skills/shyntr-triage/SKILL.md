---
name: shyntr-triage
description: Specialized skill for classifying failures, bugs, or test mismatches in the Shyntr codebase. Use this before implementation to identify the root cause and affected surface.
---

# Shyntr Triage Workflow

Use this skill to classify the problem before starting implementation work. This keeps the main context clean and ensures we don't fix the wrong thing.

## Output Requirements

1. **Exact Failure Location**: File path, line number (if possible), and function name.
2. **Classification**:
    - `implementation`: Code logic is incorrect.
    - `test`: Test expectation or assertion is wrong.
    - `fixture`: Mock data or setup state is incorrect.
    - `config`: Environment variable or static configuration mismatch.
    - `propagation`: A change was made in one layer but not propagated (e.g., Usecase changed but Handler wasn't updated).
3. **Minimum Affected Surface**: List of files that MUST be touched to fix the issue.
4. **Recommended Strategy**: Brief description of the fix.

## Rules
- Do NOT write or edit code during the triage phase.
- Stop once the classification is confident.
- If unclassifiable, state exactly what context or logs are missing.
