# 🛡️ FedRAMP & NIST 800-53 AI Security Compliance Auditor

An autonomous, serverless AI Forward Deployed Engineer (FDE) platform designed to audit enterprise cloud architectures and vendor security questionnaires against NIST SP 800-53 Rev 5 federal controls (FedRAMP High baseline).

---

## 🌐 Live Cloud Deployment

* **Live Interactive Web Dashboard**: [fedramp-compliance-auditor.streamlit.app](https://fedramp-compliance-auditor.streamlit.app)
* **Serverless Backend**: AWS Lambda (us-east-1) with public HTTPS Function URL
* **Federal Knowledge Base**: Official 1,189-control NIST SP 800-53 Rev 5 database

---

## 🏗️ System Architecture
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. EVALUATION & QA BENCHMARK LAYER                                          │
│    [ test_cases/*.json ] ──► [ run_compliance_evals.py ] ──► [ Benchmark Evals ] │
│                                      │                                      │
│                                      ▼                                      │
│                        [ NIST Database (1,189 Controls) ]                   │
│                                      ▲                                      │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ 2. CLOUD-NATIVE SERVERLESS ENGINE    │                                      │
│    [ Streamlit Cloud Frontend ]      │                                      │
│                 │ (HTTPS POST)       │                                      │
│                 ▼                    │                                      │
│    [ AWS Lambda Function URL ] ──────┼──► [ OpenAI gpt-4o-mini ]            │
│                 │                    │                                      │
│                 ▼                    │                                      │
│    [ CISO Audit Report & SSP Plan ] ─┘                                      │
└─────────────────────────────────────────────────────────────────────────────┘


---

## 📊 Evaluation Benchmark (Evals)

Automated evaluation testing across golden dataset failure scenarios (Critical Plaintext/S3 failures, Partial KMS gaps, and Zero-Trust GovCloud configurations):

| Metric | Benchmark Result |
| :--- | :--- |
| **Federal Compliance Accuracy** | **96.0% mean exact-match accuracy across 3 runs / 600 evaluations** |
| **Average Audit Latency** | **3.11 seconds mean across 3 benchmark runs** |

---

## 🛠️ Key Capabilities

- **NIST 800-53 Rev 5 Engine**: Dynamically queries all 1,189 official federal controls (AC, SC, IA, SI, AU families).
- **Decoupled Cloud Architecture**: Streamlit Cloud frontend communicating with a serverless AWS Lambda backend.
- **Modular Test Suite**: Auto-discovers and benchmarks multi-file scenarios inside `test_cases/`.
- **CISO Executive Reporting**: Generates gap analysis, mandated remediation roadmaps, and downloadable System Security Plan (SSP) markdown reports.

---

## 🚀 Quickstart

### 1. Setup & Ingest NIST Database
```bash
git clone [https://github.com/rapolu-dl/fedramp-compliance-auditor.git](https://github.com/rapolu-dl/fedramp-compliance-auditor.git)
cd fedramp-compliance-auditor
pip install -r requirements.txt

# Ingest official NIST 800-53 Rev 5 OSCAL dataset (1,189 controls)
python sync_nist_catalog.py
2. Run the Automated Evaluation Suite
Bash
python run_compliance_evals.py
3. Launch the Web Interface Locally
Bash
python -m streamlit run app.py
