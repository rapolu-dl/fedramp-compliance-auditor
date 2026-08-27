import os
from typing import Literal, List
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

# 1. Load API Key
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# 2. Define the Enterprise Compliance Schema
class ComplianceAudit(BaseModel):
    system_name: str = Field(description="Name of the application or subsystem audited")
    nist_control_family: Literal["AC_Access_Control", "SC_System_Communications", "IA_Identification_Auth", "SI_System_Integrity"]
    compliance_status: Literal["COMPLIANT", "NON_COMPLIANT", "PARTIALLY_COMPLIANT"]
    risk_level: Literal["CRITICAL", "HIGH", "MODERATE", "LOW"]
    violation_summary: str = Field(description="Clear explanation of the compliance gap")
    required_remediation: str = Field(description="Specific technical action required to meet FedRAMP/NIST standards")
    confidence_score: float = Field(ge=0.0, le=1.0)


# 3. Sample Architecture Security Description (Violating FedRAMP Encryption & Access)
sample_system_architecture = """
System: HealthPortal-API (v2.4)
Description:
The backend microservices run in a public AWS VPC. All database traffic to RDS PostgreSQL is sent over standard plaintext HTTP port 5432 with TLS disabled to reduce latency.
Administrative access to production database clusters is managed via a shared master 'admin' credential stored in an unencrypted S3 bucket accessible by all developers.
No automated credential rotation or MFA is enforced on administrative sessions.
"""

# 4. Prompt the model to extract and validate compliance
def audit_architecture(architecture_text: str) -> ComplianceAudit:
    completion = client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an expert FedRAMP / NIST 800-53 Security Compliance AI Auditor. "
                    "Analyze incoming system architecture descriptions and produce a strictly validated compliance audit report."
                ),
            },
            {"role": "user", "content": f"Audit this architecture configuration:\n{architecture_text}"},
        ],
        response_format=ComplianceAudit,
    )
    return completion.choices[0].message.parsed


# 5. Execute and Print
if __name__ == "__main__":
    result = audit_architecture(sample_system_architecture)
    print("\n=======================================================")
    print("       FEDRAMP / NIST 800-53 COMPLIANCE REPORT        ")
    print("=======================================================")
    print(f"System:            {result.system_name}")
    print(f"Control Family:    {result.nist_control_family}")
    print(f"Status:            {result.compliance_status}")
    print(f"Risk Level:        {result.risk_level}")
    print(f"Violation:         {result.violation_summary}")
    print(f"Remediation:       {result.required_remediation}")
    print(f"Confidence:        {result.confidence_score}")
    print("=======================================================\n")
