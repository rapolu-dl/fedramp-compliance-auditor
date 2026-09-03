import csv
import glob
import hashlib
import json
import os
import platform
import statistics
import time
from collections import Counter
from datetime import datetime, timezone

import compliance_agent as agent

CASES_DIR = os.getenv("BLIND_CASES_DIR", "blind_cases")
OUTPUT_CSV = os.getenv("BLIND_OUTPUT_CSV", "final_blind_run1.csv")
METADATA_JSON = os.getenv("BLIND_METADATA_JSON", "final_blind_metadata.json")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def percentile(values, p):
    if not values:
        return None
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    k = (len(values) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    frac = k - lo
    return values[lo] * (1 - frac) + values[hi] * frac


def load_cases():
    cases = []
    for path in sorted(glob.glob(os.path.join(CASES_DIR, "*.json"))):
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        obj["_source_file"] = os.path.basename(path)
        cases.append(obj)
    return cases


def main():
    cases = load_cases()
    if len(cases) != 100:
        raise RuntimeError(
            f"Expected exactly 100 blind cases in {CASES_DIR!r}; found {len(cases)}."
        )

    started = datetime.now(timezone.utc)
    rows = []
    latencies = []
    status_counts = Counter()
    risk_counts = Counter()

    print(f"Running {len(cases)} BLIND cases from {CASES_DIR}/")
    print("Expected labels are intentionally not present in this pack.")
    print()

    for i, case in enumerate(cases, 1):
        t0 = time.perf_counter()
        result = agent.audit_system(case["architecture"])
        latency = time.perf_counter() - t0
        latencies.append(latency)

        status_counts[result.overall_status] += 1
        risk_counts[result.overall_risk_score] += 1

        row = {
            "id": case["id"],
            "source_file": case["_source_file"],
            "family": case.get("family", ""),
            "control_ref": case.get("control_ref", ""),
            "actual_status": result.overall_status,
            "actual_risk": result.overall_risk_score,
            "latency_seconds": round(latency, 4),
            "violated_controls": "|".join(result.violated_controls or []),
            "audit_findings": result.audit_findings,
            "mandated_remediation": result.mandated_remediation,
        }
        rows.append(row)

        print(
            f"[{i:03d}/{len(cases)}] "
            f"{case['id']} {case.get('control_ref','')} "
            f"actual={result.overall_status}/{result.overall_risk_score} "
            f"{latency:.2f}s"
        )

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    ended = datetime.now(timezone.utc)

    metadata = {
        "benchmark": "FedRAMP/NIST Final Blind Candidate 100",
        "blind_protocol": "Expected labels withheld from cases and runner.",
        "started_utc": started.isoformat(),
        "ended_utc": ended.isoformat(),
        "case_count": len(cases),
        "model_name": getattr(agent, "MODEL_NAME", None),
        "severity_policy_version": getattr(agent, "SEVERITY_POLICY_VERSION", None),
        "python_version": platform.python_version(),
        "agent_sha256": sha256_file("compliance_agent.py")
            if os.path.exists("compliance_agent.py") else None,
        "catalog_file": getattr(agent, "NIST_CATALOG_FILE", None),
        "catalog_sha256": sha256_file(getattr(agent, "NIST_CATALOG_FILE", ""))
            if getattr(agent, "NIST_CATALOG_FILE", None)
            and os.path.exists(getattr(agent, "NIST_CATALOG_FILE")) else None,
        "catalog_metadata_file": getattr(agent, "NIST_METADATA_FILE", None),
        "catalog_metadata_sha256": sha256_file(getattr(agent, "NIST_METADATA_FILE", ""))
            if getattr(agent, "NIST_METADATA_FILE", None)
            and os.path.exists(getattr(agent, "NIST_METADATA_FILE")) else None,
        "average_latency_seconds": statistics.mean(latencies),
        "median_latency_seconds": statistics.median(latencies),
        "p95_latency_seconds": percentile(latencies, 0.95),
        "max_latency_seconds": max(latencies),
        "actual_status_distribution": dict(status_counts),
        "actual_risk_distribution": dict(risk_counts),
        "output_csv": OUTPUT_CSV,
    }

    with open(METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print()
    print("=" * 62)
    print("                 BLIND RUN COMPLETE")
    print("=" * 62)
    print(f"Cases:                  {len(cases)}")
    print(f"Average latency:        {statistics.mean(latencies):.2f}s")
    print(f"Median latency:         {statistics.median(latencies):.2f}s")
    print(f"P95 latency:            {percentile(latencies, 0.95):.2f}s")
    print(f"Raw results CSV:        {OUTPUT_CSV}")
    print(f"Run metadata:           {METADATA_JSON}")
    print()
    print("Actual status distribution:")
    for k, v in sorted(status_counts.items()):
        print(f"  {k:24s} {v}")
    print("Actual risk distribution:")
    for k, v in sorted(risk_counts.items()):
        print(f"  {k:12s} {v}")
    print("=" * 62)
    print("Do not modify the agent or cases before the answer key is scored.")


if __name__ == "__main__":
    main()
