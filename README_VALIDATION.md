# NIST / FedRAMP LLM Auditor — 100-Case Validation Pack

This pack is separate from the existing 200-case rubric-aligned regression suite.

Distribution:
- 100 cases
- 20 NIST SP 800-53 Rev. 5 families
- 5 cases per family
- 40 COMPLIANT / LOW
- 30 PARTIALLY_COMPLIANT / MODERATE
- 30 NON_COMPLIANT / CRITICAL
- 10 cases with untrusted/adversarial text

The architecture text avoids the old giveaway phrases such as "fully implemented",
"secondary control gap", and "critical observed condition".

For the cleanest first run:
1. Freeze compliance_agent.py.
2. Do not inspect the expected labels first.
3. Run all 100 once.
4. Save the raw results.
5. Do not tune the agent and continue calling this pack unseen.

Severity labels use a benchmark policy:
- LOW: requirement is affirmatively evidenced with no material in-scope defect.
- MODERATE: bounded deficiency without immediate high-impact exposure.
- CRITICAL: active/direct high-impact security, privacy, privileged-access, availability,
  audit-integrity, or supply-chain exposure.

This severity mapping is not claimed to be a universal NIST/FedRAMP severity scale.
