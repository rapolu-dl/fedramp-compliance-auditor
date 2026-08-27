import os
import json
from typing import Literal, List
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

# 1. Load API Key
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------------------------------------------
# 2. DEFINE THE TOOLS (NIST Catalog & Cloud Posture APIs)
# -------------------------------------------------------------
def lookup_nist_control(control_id: str) -> str:
    """Fetches the official NIST 800-53 Rev 5 federal control requirements."""
    catalog = {
        "SC-8": (
            "NIST 800-53 Rev 5: SC-8 (Transmission Confidentiality and Integrity)\n"
            "Requirement: The information system must protect the confidentiality and integrity of transmitted information. "
            "FedRAMP High Baseline: Mandatory TLS 1.3/1.2 encryption for all internal and external data in transit. Plaintext HTTP/port 5432 is strictly prohibited."
        ),
        "IA-2": (
            "NIST 800-53 Rev 5: IA-2 (Identification and Authentication)\n"
            "Requirement: Uniquely identify and authenticate organizational users. "
            "FedRAMP High Baseline: Multi-factor authentication (MFA) is mandatory for all administrative access. Shared service accounts without unique attribution are strictly prohibited."
        ),
        "AC-2": (
            "NIST 800-53 Rev 5: AC-2 (Account Management)\n"
            "Requirement: Manage information system accounts, including establishing, activating, modifying, and reviewing. "
            "FedRAMP High Baseline: Automated credential rotation every 90 days is required. Static master credentials stored in cleartext are a critical audit failure."
        )
    }
    control = catalog.get(control_id.upper())
    if control:
        return control
    return f"Control ID {control_id} not found in catalog."


def check_cloud_asset_posture(asset_id: str) -> str:
    """Queries live AWS/Azure cloud security posture for an asset."""
    mock_assets = {
        "rds-postgres-main": {
            "tls_enabled": False,
            "port": 5432,
            "publicly_accessible": True,
            "storage_encrypted": False
        },
        "s3-admin-credentials": {
            "default_encryption": "None",
            "public_access_block": False,
            "versioning": False
        }
    }
    asset = mock_assets.get(asset_id)
    return json.dumps(asset if asset else {"error": f"Asset {asset_id} not found."})


tools = [
    {
        "type": "function",
        "function": {
            "name": "lookup_nist_control",
            "description": "Fetch official federal requirements for a NIST 800-53 Rev 5 control (e.g. SC-8, IA-2, AC-2)",
            "parameters": {
                "type": "object",
                "properties": {
                    "control_id": {"type": "string", "description": "The NIST control ID (e.g., 'SC-8', 'IA-2')"}
                },
                "required": ["control_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_cloud_asset_posture",
            "description": "Query the live security posture of a cloud asset (e.g., 'rds-postgres-main', 's3-admin-credentials')",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "The cloud resource identifier"}
                },
                "required": ["asset_id"]
            }
        }
    }
]

# -------------------------------------------------------------
# 3. STRUCTURED CISO AUDIT REPORT
# -------------------------------------------------------------
class NISTComplianceReport(BaseModel):
    system_name: str
    overall_status: Literal["COMPLIANT", "NON_COMPLIANT", "PARTIALLY_COMPLIANT"]
    overall_risk_score: Literal["CRITICAL", "HIGH", "MODERATE", "LOW"]
    violated_controls: List[str] = Field(description="List of specific NIST 800-53 control IDs violated (e.g. ['SC-8', 'IA-2'])")
    audit_findings: str = Field(description="Detailed technical audit findings with exact citations")
    mandated_remediation: str = Field(description="Step-by-step technical fix to satisfy FedRAMP High requirements")
    ciso_executive_summary: str = Field(description="2-sentence executive summary ready for CISO/Auditor submission")

# -------------------------------------------------------------
# 4. AGENT EXECUTION LOOP
# -------------------------------------------------------------
def run_compliance_auditor(architecture_text: str) -> NISTComplianceReport:
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert FedRAMP / NIST 800-53 Security Auditor. "
                "Inspect the incoming architecture description. Use your tools to look up official NIST controls "
                "and check live asset posture before compiling your final audit report."
            )
        },
        {"role": "user", "content": f"Audit this architecture:\n{architecture_text}"}
    ]

    # Step 4a: Let the AI decide which tools to call
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        tools=tools,
        tool_choice="auto"
    )
    response_msg = response.choices[0].message
    messages.append(response_msg)

    # Step 4b: Execute tools requested by the AI
    if response_msg.tool_calls:
        for tool_call in response_msg.tool_calls:
            func_name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)
            
            if func_name == "lookup_nist_control":
                control_id = args.get("control_id")
                print(f"-> Agent calling tool: lookup_nist_control('{control_id}')")
                tool_output = lookup_nist_control(control_id)
            elif func_name == "check_cloud_asset_posture":
                asset_id = args.get("asset_id")
                print(f"-> Agent calling tool: check_cloud_asset_posture('{asset_id}')")
                tool_output = check_cloud_asset_posture(asset_id)
            else:
                tool_output = "Unknown tool"

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": tool_output
            })

    # Step 4c: Get final structured report from the AI
    final_completion = client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=messages,
        response_format=NISTComplianceReport
    )
    return final_completion.choices[0].message.parsed


# -------------------------------------------------------------
# 5. EXECUTION WITH REALISTIC ARCHITECTURE INPUT
# -------------------------------------------------------------
test_architecture = """
System: HealthPortal-API (v2.4)
Components:
- Database: rds-postgres-main (Communicating via plaintext port 5432, TLS is disabled)
- Credential Storage: s3-admin-credentials (Shared admin password stored in plaintext file, no MFA required for developers)
"""

if __name__ == "__main__":
    print("\n--- STARTING FEDRAMP / NIST COMPLIANCE AUDIT ---")
    report = run_compliance_auditor(test_architecture)
    print("\n=======================================================")
    print(f"System:                {report.system_name}")
    print(f"Status:                {report.overall_status}")
    print(f"Risk Score:            {report.overall_risk_score}")
    print(f"Violated Controls:     {', '.join(report.violated_controls)}")
    print(f"\n[ DETAILED FINDINGS ]\n{report.audit_findings}")
    print(f"\n[ MANDATED REMEDIATION ]\n{report.mandated_remediation}")
    print(f"\n[ CISO EXECUTIVE SUMMARY ]\n{report.ciso_executive_summary}")
    print("=======================================================\n")
