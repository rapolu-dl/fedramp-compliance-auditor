# NIST / FedRAMP LLM Auditor — Validation Pack V2

## What changed

The original V1 pack used only LOW, MODERATE, and CRITICAL expected-risk labels.
V2 adds a meaningful HIGH tier and re-adjudicates the cases under a four-level policy.

V2 distribution:

- COMPLIANT / LOW: 40
- PARTIALLY_COMPLIANT / MODERATE: 29
- NON_COMPLIANT / HIGH: 12
- NON_COMPLIANT / CRITICAL: 19
- Total: 100

Exactly 12 V1 labels changed.

## Scientific status

The first run was observed before this adjudication, so this V2 pack must **not** be reported as a new blind holdout result.
Use it as a post-hoc adjudicated engineering regression/validation set.

A future final publication benchmark should be a new untouched pack created after the agent and rubric are frozen.

## Files

- `test_cases_validation_v2/` — 100 adjudicated JSON cases
- `SEVERITY_RUBRIC_V2.md` — frozen four-level decision policy
- `validation_manifest_v2.csv` — complete V1 → V2 audit trail
- `ADJUDICATION_CHANGES_V2.csv` — only changed cases
- `run_validation_evals_v2.py` — runner for the V2 folder
- `RUN1_RESCORING_V2.md` — post-hoc engineering comparison against the already-observed first run
- `SHA256SUMS_V2.txt` — integrity hashes
