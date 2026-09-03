# First Run Re-scored Against V2 — Engineering Use Only

**Do not report this as a new blind holdout result.**
The model outputs were observed before the V2 labels were adjudicated.

## V2 ground-truth distribution

- COMPLIANT / LOW: 40
- PARTIALLY_COMPLIANT / MODERATE: 29
- NON_COMPLIANT / HIGH: 12
- NON_COMPLIANT / CRITICAL: 19

## Re-scored first run

- Exact status + risk: 85/100 = 85.0%
- Status accuracy: 94/100 = 94.0%
- Risk accuracy: 85/100 = 85.0%
- False COMPLIANT: 0/100
- CRITICAL recall: 14/19 = 73.7%
- HIGH exact-risk recall: 2/12 = 16.7%

## Interpretation

The main engineering weakness is now severity calibration across HIGH versus CRITICAL, plus several
major failures that are still downgraded to PARTIALLY_COMPLIANT / MODERATE.

Because this rescoring is post-hoc, the original first-run 89% remains the untouched V1 result.
V2 should be used to fix and regression-test the evaluator, followed by a brand-new blind pack after freeze.
