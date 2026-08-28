# FedRAMP / NIST SP 800-53 Rev. 5 — 200-Case Evaluation Pack

## Purpose

This pack is designed to run **without modifying** the repository's current
`run_compliance_evals.py`. The evaluator auto-discovers every `*.json` file
directly under `test_cases/` and compares:

- `result.overall_status` with `expected_status`
- `result.overall_risk_score` with `expected_risk`

This pack contains exactly **200 JSON test cases**, including the four cases
already present in the public repository and 196 additional cases.

## Coverage

- 20 NIST SP 800-53 Rev. 5 control families
- 10 cases per family
- 80 COMPLIANT / LOW cases
- 80 PARTIALLY_COMPLIANT / MODERATE cases
- 40 NON_COMPLIANT / CRITICAL cases
- Includes a subset of adversarial evidence strings to test whether untrusted
  text can improperly influence the audit verdict.

The 196 new cases are **synthetic**. They are not represented as real federal,
customer, employer, or production logs. They are deliberately structured
architecture/evidence scenarios because the current evaluator consumes the
`architecture` string rather than raw CloudTrail/Terraform/YAML files.

## Ground-truth rule used for this pack

The expected labels are aligned to the current `compliance_agent.py` rubric:

- NON_COMPLIANT / CRITICAL: explicit plaintext transport, unencrypted
  credentials in S3, missing MFA for administrator access, or a publicly
  accessible database.
- PARTIALLY_COMPLIANT / MODERATE: core transport/MFA protections are present
  but a secondary control deficiency remains.
- COMPLIANT / LOW: strict mTLS/TLS, customer-managed encryption, private
  endpoints, hardware-backed MFA, plus affirmative family-control evidence.

This makes the pack a **rubric-aligned synthetic stress test**, not an
independently adjudicated real-world FedRAMP certification dataset.

## How to use

From the repository root:

1. Back up the current `test_cases/` folder if desired.
2. Replace its contents with the JSON files from this pack's `test_cases/`.
3. Confirm your OpenAI API key and dependencies are configured.
4. Run:

    python run_compliance_evals.py

To save the console output on macOS/Linux:

    python run_compliance_evals.py | tee benchmark_run_200.txt

PowerShell:

    python run_compliance_evals.py | Tee-Object benchmark_run_200.txt

## Important research note

Do **not** treat the script's hard-coded "$0.50 per 1,000" output as a measured
cost result. Actual API cost depends on token usage and current model pricing.

Likewise, the current evaluator scores only the pair:
`overall_status + overall_risk_score`. It does not yet compute control-level
precision/recall/F1. Any Springer manuscript should describe the metric exactly
as implemented unless a later evaluation harness measures those additional
metrics.

## Provenance and sources used to design the suite

The suite is grounded in:
- NIST SP 800-53 Rev. 5 control-family structure and control themes.
- The repository's current `nist_full_catalog.json`, evaluator rubric, and
  original four JSON test cases.
- FedRAMP's current machine-readable rules ecosystem as contextual guidance.

See `benchmark_manifest.csv` for the primary family/control reference,
scenario style, provenance, and ground-truth rationale for every case.

Generated benchmark cases: 196
Total test cases: 200
