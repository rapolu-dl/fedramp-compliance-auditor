import time
from compliance_agent import audit_system

# Golden Evaluation Dataset across 3 distinct Federal Scenarios
compliance_eval_dataset = [
    {
        "test_name": "Critical Failure (Plaintext DB & Unencrypted S3)",
        "architecture": (
            "System: HealthPortal-API\n"
            "Components: rds-postgres-main (plaintext port 5432, no TLS), "
            "s3-admin-credentials (unencrypted shared password file, no MFA)."
        ),
        "expected_status": "NON_COMPLIANT",
        "expected_risk": "CRITICAL"
    },
    {
        "test_name": "Zero-Trust Sovereign GovCloud (Fully Compliant)",
        "architecture": (
            "System: GovCloud-PaymentGateway\n"
            "Components: prod-zero-trust-mesh (Istio mTLS strict, AWS KMS CMK encryption at rest, "
            "IAM Identity Center hardware MFA enforced, all public ingress blocked via PrivateLink)."
        ),
        "expected_status": "COMPLIANT",
        "expected_risk": "LOW"
    },
    {
        "test_name": "Partially Compliant (TLS Active, Missing KMS CMK)",
        "architecture": (
            "System: Staging-Gateway\n"
            "Components: staging-api-gateway (TLS 1.3 enabled, MFA enforced, but using default AWS managed keys instead of KMS CMK)."
        ),
        "expected_status": "PARTIALLY_COMPLIANT",
        "expected_risk": "MODERATE"
    }
]

def run_benchmark():
    print("\n=======================================================")
    print("   RUNNING FEDRAMP / NIST COMPLIANCE EVALS BENCHMARK   ")
    print("=======================================================\n")

    passed_tests = 0
    total_tests = len(compliance_eval_dataset)
    total_latency = 0.0

    for i, test in enumerate(compliance_eval_dataset, 1):
        print(f"[{i}/{total_tests}] Testing Scenario: '{test['test_name']}'...")
        
        start_time = time.time()
        result = audit_system(test["architecture"])
        elapsed = time.time() - start_time
        total_latency += elapsed

        status_match = (result.overall_status == test["expected_status"])
        risk_match = (result.overall_risk_score == test["expected_risk"])

        is_passed = status_match and risk_match

        if is_passed:
            passed_tests += 1
            badge = "PASS ✅"
        else:
            badge = "FAIL ❌"

        print(f"      -> Status: {badge} | Latency: {elapsed:.2f}s")
        print(f"      -> Output: Status={result.overall_status} | RiskScore={result.overall_risk_score}\n")

    accuracy_rate = (passed_tests / total_tests) * 100
    avg_latency = total_latency / total_tests

    print("=======================================================")
    print("         FEDRAMP AUDIT AGENT BENCHMARK REPORT          ")
    print("=======================================================")
    print(f"Total Scenarios Evaluated:   {total_tests}")
    print(f"Compliance Accuracy:         {accuracy_rate:.1f}%")
    print(f"Average Audit Latency:       {avg_latency:.2f} seconds")
    print(f"Estimated Cost per 1,000:    $0.50 USD")
    print("=======================================================\n")

if __name__ == "__main__":
    run_benchmark()
