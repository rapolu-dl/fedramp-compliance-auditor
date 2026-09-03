# Final Blind Candidate — First-Run Protocol

This pack contains **100 new synthetic cases** spanning all 20 NIST SP 800-53 Rev. 5 control families.

## Why this pack is different

The public case files contain only:
- case ID
- family
- target control reference
- architecture/evidence text

They contain **no expected status, no expected risk, no ground-truth rationale, and no pass/fail labels**.

The runner also contains no answer key. It records only the agent's outputs.

The answer key was fixed before the first run and committed by SHA-256:

`fe12943bcee32a6196d5a6e1234fd48f1197add5f9316f2952defe1b871247d8`

After the first run is complete, the answer key can be revealed and its SHA-256 verified against this commitment. This prevents changing expected labels after seeing the model outputs.

## First-run procedure

1. Freeze the current `compliance_agent.py`.
2. Do not inspect or edit the blind case JSON files before the first run.
3. Do not change the model, prompt, catalog, or severity policy.
4. Run:

```bash
python run_final_blind_eval.py | tee final_blind_run1.txt
```

5. When all 100 cases finish, preserve these three files:
   - `final_blind_run1.txt`
   - `final_blind_run1.csv`
   - `final_blind_metadata.json`
6. Upload all three for scoring against the pre-committed answer key.
7. Do not tune the agent before scoring.

## Interpretation

This is a **blind holdout candidate relative to execution** because expected labels are not exposed to the agent or runner.

It is still a synthetic benchmark created within the same research workflow after the V3 architecture was designed. It is therefore stronger than the earlier development/regression sets, but it is **not equivalent to independently labeled SME/3PAO ground truth**.

The benchmark evaluates status/risk agreement under the project's frozen four-level severity policy. It does not establish FedRAMP authorization accuracy.
