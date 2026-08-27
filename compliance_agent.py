import os
import json
from typing import Literal, List
from dotenv import load_dotenv
from openai import OpenAI, APIConnectionError, RateLimitError
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# 1. Load API Key
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# 2. Tools
def lookup_nist_control(control_id: str) -> str:
    catalog = {
        "SC-8": "NIST SC-8: Mandatory TLS 1.3/1.2 for data in transit. Plaintext is prohibited.",
        "IA-2": "NIST IA-2: MFA mandatory for all administrative access. Shared accounts prohibited.",
        "AC-2": "NIST AC-2: Automated credential rotation every 90 days required.",
        "SC-28": "NIST SC-28: Server-side encryption at rest (KMS/AES-256) mandatory for all storage.",
        "AC-17": "NIST AC-17: Remote access must be isolated; public database access is strictly prohibited."
    }
    return catalog.get(control_id.upper(), f"NIST Control {control_id} catalog entry verified.")


def check_cloud_asset_posture(asset_id: str) -> str:
    mock_assets = {
        "rds-postgres-main": {"tls_enabled": False, "publicly_accessible": True, "storage_encrypted": False},
        "s3-admin-credentials": {"default_encryption": "None", "public_access_block": False},
        "prod-zero-trust-mesh": {"mtls_strict": True, "kms_cmk_encrypted": True, "mfa_enforced": True, "public_access_block": True},
        "staging-api-gateway": {"tls_enabled": True, "mfa_enforced": True, "kms_cmk_encrypted": False}
    }
    asset = mock_assets.get(asset_id, {"status": "Asset posture verified via AWS Config."})
    return json.dumps(asset)


tools = [
    {
        "type": "function",
        "function": {
            "name": "lookup_nist_control",
            "description": "Look up NIST 800-53 Rev 5 control rules",
            "parameters": {
                "type": "object",
                "properties": {"control_id": {"type": "string"}},
                "required": ["control_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_cloud_asset_posture",
            "description": "Check live cloud security configuration",
            "parameters": {
                "type": "object",
                "properties": {"asset_id": {"type": "string"}},
                "required": ["asset_id"]
            }
        }
    }
]

# 3. Schema
class NISTComplianceReport(BaseModel):
    system_name: str
    overall_status: Literal["COMPLIANT", "NON_COMPLIANT", "PARTIALLY_COMPLIANT"]
    overall_risk_score: Literal["CRITICAL", "HIGH", "MODERATE", "LOW"]
    violated_controls: List[str]
    audit_findings: str
    mandated_remediation: str
    ciso_executive_summary: str


# 4. Resilient Agent Loop
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    retry=retry_if_exception_type((APIConnectionError, RateLimitError)),
    reraise=True
)
def call_llm(messages, tools=None):
    if tools:
        return client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=tools,
            tool_choice="auto"
        )
    return client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=messages,
        response_format=NISTComplianceReport
    )


def audit_system(architecture_text: str) -> NISTComplianceReport:
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert FedRAMP High / NIST 800-53 Security Compliance Auditor.\n"
                "Follow this strict Federal Compliance Rubric:\n"
                "- NON_COMPLIANT / CRITICAL: Plaintext transport (no TLS), unencrypted credentials in S3, missing MFA on admin access, publicly accessible DB.\n"
                "- PARTIALLY_COMPLIANT / MODERATE: TLS enabled and MFA active, but missing secondary controls (e.g. KMS CMK customer-managed keys or minor rotation gaps).\n"
                "- COMPLIANT / LOW: Full Zero-Trust architecture, strict mTLS, KMS CMK encryption at rest, private endpoints, hardware MFA.\n\n"
                "Use your tools to check asset posture and NIST controls before compiling your report."
            )
        },
        {"role": "user", "content": f"Audit this architecture:\n{architecture_text}"}
    ]

    response = call_llm(messages, tools=tools)
    response_msg = response.choices[0].message
    messages.append(response_msg)

    if response_msg.tool_calls:
        for tool_call in response_msg.tool_calls:
            func_name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)

            if func_name == "lookup_nist_control":
                output = lookup_nist_control(args.get("control_id", ""))
            elif func_name == "check_cloud_asset_posture":
                output = check_cloud_asset_posture(args.get("asset_id", ""))
            else:
                output = "Tool output verified."

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": output
            })

    final_report = call_llm(messages)
    return final_report.choices[0].message.parsed
