import os
import glob
import json
import time
import csv
from collections import Counter
from compliance_agent import audit_system

TEST_CASES_DIR = os.getenv("VALIDATION_CASES_DIR", "test_cases_validation")
OUTPUT_CSV = os.getenv("VALIDATION_OUTPUT_CSV", "validation_results.csv")

def load_cases(directory):
    cases = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            obj["_source_file"] = os.path.basename(path)
            cases.append(obj)
    return cases

def main():
    cases = load_cases(TEST_CASES_DIR)
    if not cases:
        raise RuntimeError(f"No JSON cases found in {TEST_CASES_DIR!r}")

    rows = []
    exact = status_ok = risk_ok = 0
    total_latency = 0.0
    confusion = Counter()

    print(f"Running {len(cases)} validation cases from {TEST_CASES_DIR}/")

    for i, case in enumerate(cases, 1):
        start = time.time()
        result = audit_system(case["architecture"])
        latency = time.time() - start
        total_latency += latency

        s = result.overall_status == case["expected_status"]
        r = result.overall_risk_score == case["expected_risk"]
        e = s and r

        status_ok += int(s)
        risk_ok += int(r)
        exact += int(e)
        confusion[(case["expected_status"], result.overall_status)] += 1

        rows.append({
            "id": case["id"],
            "source_file": case["_source_file"],
            "control_ref": case.get("control_ref", ""),
            "expected_status": case["expected_status"],
            "actual_status": result.overall_status,
            "expected_risk": case["expected_risk"],
            "actual_risk": result.overall_risk_score,
            "exact_match": e,
            "latency_seconds": round(latency, 3),
            "violated_controls": "|".join(getattr(result, "violated_controls", []) or []),
            "audit_findings": getattr(result, "audit_findings", ""),
        })

        print(
            f"[{i:03d}/{len(cases)}] {case['id']} {case.get('control_ref','')} "
            f"{'PASS' if e else 'FAIL'} "
            f"expected={case['expected_status']}/{case['expected_risk']} "
            f"actual={result.overall_status}/{result.overall_risk_score} "
            f"{latency:.2f}s"
        )

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    n = len(cases)
    print("\n=======================================================")
    print("              VALIDATION BENCHMARK REPORT")
    print("=======================================================")
    print(f"Cases:                  {n}")
    print(f"Exact status+risk:      {exact}/{n} = {100*exact/n:.1f}%")
    print(f"Status accuracy:        {status_ok}/{n} = {100*status_ok/n:.1f}%")
    print(f"Risk accuracy:          {risk_ok}/{n} = {100*risk_ok/n:.1f}%")
    print(f"Average latency:        {total_latency/n:.2f}s")
    print(f"Results CSV:            {OUTPUT_CSV}")
    print("=======================================================")

    print("\nStatus confusion counts:")
    for (expected, actual), count in sorted(confusion.items()):
        print(f"  expected={expected:22s} actual={actual:22s} count={count}")

if __name__ == "__main__":
    main()
