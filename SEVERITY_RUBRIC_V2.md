# Four-Level Severity Rubric — V2

This rubric is a **benchmark policy for this project**. It is not presented as a universal risk scale mandated by NIST or FedRAMP.

## Canonical status/risk pairs

| Status | Risk | Decision rule |
|---|---|---|
| COMPLIANT | LOW | No material in-scope deficiency; supplied evidence affirmatively supports the target requirement. |
| PARTIALLY_COMPLIANT | MODERATE | Real but bounded deficiency; limited scope and/or effective compensating controls; no immediate severe exposure. |
| NON_COMPLIANT | HIGH | Major control requirement absent or materially ineffective; significant impact potential; no confirmed active severe event/exposure. |
| NON_COMPLIANT | CRITICAL | Current/confirmed severe condition or immediate direct severe exposure. |

## R1 — LOW

Use LOW only when the evidence affirmatively supports the target requirement and no material in-scope deficiency is described.

## R2 — MODERATE

Use MODERATE when a genuine deficiency exists but all of the following are true:
- the scope is bounded, limited, stale, or overdue rather than fundamentally absent;
- useful compensating controls remain;
- there is no evidence of current severe exposure, compromise, destructive activity, or significant unauthorized use.

## R3 — HIGH

Use HIGH when a major control is absent or materially ineffective in production and the potential impact is significant, but the evidence does **not** establish a current/confirmed severe event.

Examples:
- major assessment/authorization gaps after architecture changes;
- absent privileged auditability;
- broken recovery capability before an actual outage;
- serious privileged-access weakness without demonstrated misuse;
- sensitive production system outside governance/authorization inventory;
- supplier security obligations materially absent without evidence of actual disclosure;
- sensitive data unencrypted at rest but not shown publicly disclosed.

## R4 — CRITICAL

Use CRITICAL when at least one of these is directly evidenced:
- active compromise, destructive malware, or continuing high-impact incident;
- actual sensitive-data disclosure/loss or transfer outside intended trust without protection;
- actual unauthorized privileged use;
- direct public exposure of a sensitive production resource or privileged interface;
- active transmission/exposure of sensitive credentials without protection;
- internet-facing known exploitable critical vulnerability without mitigation;
- confirmed integrity-bypassed/tampered software or firmware running in production.

## Important rule

Do not infer a CRITICAL condition merely because the potential impact *could* be severe.
CRITICAL requires direct evidence of an active/current severe condition or immediate direct severe exposure.

## Holdout status

The first 100-case run was already observed before this V2 adjudication. Therefore V2 is now a
**post-hoc adjudicated regression/validation set**, not an untouched blind holdout.
