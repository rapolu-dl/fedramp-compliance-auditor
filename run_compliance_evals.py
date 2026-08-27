import os
import glob
import json
import time
from compliance_agent import audit_system

TEST_CASES_DIR = "test_cases"

def load_all_test_cases(directory: str):
    """Auto-discovers and loads all .json files in the test directory."""
    if not os.path.exists(directory):
        raise FileNotFoundError(f"Directory '{directory}' does not exist.")
    
    json_files = sorted(glob.glob(os.path.join(directory, "*.json")))
    test_cases = []
    
    for file_path in json_files:
        with open(file_path, "r") as f:
            data = json.load(f)
            data["_source_file"] = os.path.basename(file_path)
            test_cases.append(data)
            
    return test_cases


def run_benchmark():
    test_cases = load_all_test_cases(TEST_CASES_DIR)
    
    print("\n=======================================================")
    print(f"   RUNNING FEDRAMP / NIST COMPLIANCE EVALUATION SUITE  ")
    print(f"   Auto-discovered {len(test_cases)} test case files in '{TEST_CASES_DIR}/'")
    print("=======================================================\n")

    passed_tests = 0
    total_tests = len(test_cases)
    total_latency = 0.0

    for i, test in enumerate(test_cases, 1):
        test_id = test.get("id", f"TC-{i:03d}")
        test_name = test.get("test_name", "Unnamed Scenario")
        file_name = test.get("_source_file", "")
        
        print(f"[{i}/{total_tests}] [{test_id}] [{file_name}]")
        print(f"      Scenario: '{test_name}'...")
        
        start_time = time.time()
        result = audit_system(test["architecture"])
        elapsed = time.time() - start_time
        total_latency += elapsed

        # Match against result.overall_status and result.overall_risk_score
        status_match = (result.overall_status == test["expected_status"])
        risk_match = (result.overall_risk_score == test["expected_risk"])

        is_passed = status_match and risk_match

        if is_passed:
            passed_tests += 1
            badge = "PASS ✅"
        else:
            badge = "FAIL ❌"

        print(f"      -> Verdict: {badge} | Latency: {elapsed:.2f}s")
        print(f"      -> Output: Status={result.overall_status} | Risk={result.overall_risk_score}\n")

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