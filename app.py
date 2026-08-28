import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

import streamlit as st


# ============================================================
# Page configuration
# ============================================================

st.set_page_config(
    page_title="FedRAMP & NIST SP 800-53 AI Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# Reference scenarios
# ============================================================

REFERENCE_SCENARIOS = {
    "Critical — Plaintext DB & Unencrypted S3": """
Enterprise application architecture:
- Production database accepts plaintext application connections; TLS is disabled.
- An S3 bucket stores administrative credentials without encryption.
- Administrative accounts do not enforce MFA.
- Database access is reachable from a broad network path.
- Logging is enabled, but the above controls remain unresolved.

Assess the architecture against NIST SP 800-53 Rev. 5 / FedRAMP High-aligned security expectations.
""".strip(),
    "Compliant — Zero-Trust GovCloud": """
AWS GovCloud reference architecture:
- Strict mutual TLS is enforced for service-to-service traffic.
- Data at rest is encrypted with a customer-managed AWS KMS key.
- Administrative access requires hardware-backed MFA.
- Databases and internal services use private endpoints / PrivateLink.
- Public database ingress is prohibited.
- Centralized logging and security monitoring are enabled.

Assess the architecture against NIST SP 800-53 Rev. 5 / FedRAMP High-aligned security expectations.
""".strip(),
    "Partial — TLS + MFA, Missing Customer-Managed KMS Key": """
Cloud application architecture:
- TLS 1.3 protects data in transit.
- Administrative MFA is enabled.
- Storage encryption is enabled, but the environment relies on provider-managed default keys rather than a customer-managed KMS key.
- Services use private network paths and the database is not publicly accessible.
- Logging and monitoring are enabled.

Assess the architecture against NIST SP 800-53 Rev. 5 / FedRAMP High-aligned security expectations.
""".strip(),
    "Critical — Public Database Ingress": """
Production cloud architecture:
- Application traffic uses TLS.
- Storage encryption is enabled.
- Administrative MFA is enabled.
- The production database security group permits direct public ingress from 0.0.0.0/0.
- Logging and monitoring are enabled.

Assess the architecture against NIST SP 800-53 Rev. 5 / FedRAMP High-aligned security expectations.
""".strip(),
    "Custom Architecture": "",
}


# ============================================================
# Helpers
# ============================================================

def _secret_or_env(*names: str) -> Optional[str]:
    """
    Return the first configured environment variable.

    Streamlit Community Cloud exposes root-level secrets as environment
    variables. Using os.getenv here also avoids local "No secrets files found"
    warnings when no .streamlit/secrets.toml file exists.
    """
    for name in names:
        value = os.getenv(name)
        if value:
            return value.strip()

    return None


def get_lambda_url() -> Optional[str]:
    return _secret_or_env(
        "LAMBDA_FUNCTION_URL",
        "AWS_LAMBDA_URL",
        "LAMBDA_URL",
        "FUNCTION_URL",
    )


def _model_to_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value

    if hasattr(value, "model_dump"):
        return value.model_dump()

    if hasattr(value, "dict"):
        return value.dict()

    raise TypeError(f"Unsupported audit result type: {type(value).__name__}")


def normalize_backend_response(payload: Any) -> Dict[str, Any]:
    """
    Normalize common AWS Lambda Function URL / direct-agent response shapes.
    """
    if not isinstance(payload, dict):
        raise ValueError("Backend returned a non-JSON object.")

    # AWS Lambda proxy response shape:
    # {"statusCode": 200, "body": "{\"overall_status\": ...}"}
    if "statusCode" in payload:
        status_code = int(payload.get("statusCode", 500))
        body = payload.get("body")

        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                body = {"message": body}

        if status_code >= 400:
            message = body.get("message") if isinstance(body, dict) else str(body)
            raise RuntimeError(f"Lambda returned HTTP {status_code}: {message}")

        if isinstance(body, dict):
            payload = body

    # Some handlers wrap the actual result.
    for wrapper_key in ("result", "audit_result", "data"):
        wrapped = payload.get(wrapper_key)
        if isinstance(wrapped, dict):
            payload = wrapped
            break

    if payload.get("errorMessage"):
        raise RuntimeError(str(payload["errorMessage"]))

    return payload


def invoke_remote_lambda(architecture: str, lambda_url: str) -> Dict[str, Any]:
    request_body = json.dumps({"architecture": architecture}).encode("utf-8")

    request = urllib.request.Request(
        lambda_url,
        data=request_body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Lambda request failed with HTTP {exc.code}: {error_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach AWS Lambda: {exc.reason}") from exc

    try:
        payload = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AWS Lambda returned a response that was not valid JSON.") from exc

    return normalize_backend_response(payload)


def invoke_local_agent(architecture: str) -> Dict[str, Any]:
    try:
        from compliance_agent import audit_system
    except Exception as exc:
        raise RuntimeError(
            "No AWS Lambda Function URL is configured, and the local "
            "compliance_agent could not be imported."
        ) from exc

    result = audit_system(architecture)
    return normalize_backend_response(_model_to_dict(result))


def run_audit(architecture: str) -> tuple[Dict[str, Any], str]:
    """
    Prefer the serverless Lambda backend. Fall back to the local agent so
    the app can still run during local development.
    """
    lambda_url = get_lambda_url()

    if lambda_url:
        return invoke_remote_lambda(architecture, lambda_url), "AWS Lambda"

    return invoke_local_agent(architecture), "Local compliance_agent"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _display_item(item: Any) -> None:
    if isinstance(item, dict):
        st.json(item)
    else:
        st.markdown(str(item))


def _render_collection(value: Any, empty_message: str) -> None:
    items = _as_list(value)
    if not items:
        st.caption(empty_message)
        return

    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            # Prefer a readable title when one exists.
            title = (
                item.get("control_id")
                or item.get("id")
                or item.get("title")
                or item.get("control")
            )
            if title:
                with st.expander(str(title), expanded=True):
                    st.json(item)
            else:
                st.json(item)
        else:
            st.markdown(f"{index}. {item}")


def build_markdown_report(result: Dict[str, Any], architecture: str) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    status = result.get("overall_status", "UNKNOWN")
    risk = result.get("overall_risk_score", "UNKNOWN")
    summary = result.get("ciso_executive_summary", "")

    lines = [
        "# FedRAMP / NIST SP 800-53 AI Security Audit Report",
        "",
        f"**Generated:** {generated_at}",
        f"**Overall Status:** {status}",
        f"**Overall Risk:** {risk}",
        "",
        "## Architecture Security Specification",
        "",
        architecture,
        "",
        "## CISO Executive Summary",
        "",
        str(summary) if summary else "No executive summary returned.",
        "",
        "## Violated Controls",
        "",
    ]

    controls = _as_list(result.get("violated_controls"))
    if controls:
        for item in controls:
            if isinstance(item, dict):
                lines.append(f"- `{json.dumps(item, ensure_ascii=False)}`")
            else:
                lines.append(f"- {item}")
    else:
        lines.append("- None reported")

    lines.extend(["", "## Audit Findings", ""])
    findings = _as_list(result.get("audit_findings"))
    if findings:
        for item in findings:
            if isinstance(item, dict):
                lines.append(f"- `{json.dumps(item, ensure_ascii=False)}`")
            else:
                lines.append(f"- {item}")
    else:
        lines.append("- None reported")

    lines.extend(["", "## Mandated Remediation", ""])
    remediation = _as_list(result.get("mandated_remediation"))
    if remediation:
        for item in remediation:
            if isinstance(item, dict):
                lines.append(f"- `{json.dumps(item, ensure_ascii=False)}`")
            else:
                lines.append(f"- {item}")
    else:
        lines.append("- None reported")

    lines.extend(
        [
            "",
            "## Research Prototype Notice",
            "",
            (
                "This output supports security and compliance analysis but does not "
                "replace a formal FedRAMP assessment, authorization process, or "
                "independent 3PAO validation."
            ),
            "",
        ]
    )

    return "\n".join(lines)


def status_icon(status: str) -> str:
    normalized = status.upper()
    if normalized == "COMPLIANT":
        return "✅"
    if normalized == "PARTIALLY_COMPLIANT":
        return "⚠️"
    if normalized == "NON_COMPLIANT":
        return "🚨"
    return "ℹ️"


def risk_icon(risk: str) -> str:
    normalized = risk.upper()
    if normalized == "CRITICAL":
        return "🔴"
    if normalized == "HIGH":
        return "🟠"
    if normalized == "MODERATE":
        return "🟡"
    if normalized == "LOW":
        return "🟢"
    return "⚪"


def load_selected_scenario() -> None:
    selected = st.session_state.get("reference_scenario", "Custom Architecture")
    st.session_state["architecture_spec"] = REFERENCE_SCENARIOS.get(selected, "")


# ============================================================
# Research / Publication Companion Header
# ============================================================

st.markdown(
    """
    <div style="
        padding: 1.4rem 1.6rem;
        border: 1px solid rgba(128,128,128,0.25);
        border-radius: 14px;
        margin-bottom: 1rem;
    ">
        <h1 style="margin-bottom:0.3rem;">
            🛡️ FedRAMP & NIST SP 800-53 AI Security Auditor
        </h1>
        <p style="font-size:1.05rem; margin-bottom:0.4rem;">
            Evidence-grounded AI compliance assessment and
            System Security Plan (SSP) support for cloud architectures.
        </p>
        <p style="opacity:0.75; margin-bottom:0;">
            NIST SP 800-53 Rev. 5 · FedRAMP High-aligned ·
            Serverless AWS architecture
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# Empirical Benchmark
# ============================================================

st.subheader("📊 Empirical Evaluation")

metric1, metric2, metric3, metric4 = st.columns(4)

with metric1:
    st.metric(
        label="Mean Accuracy",
        value="96.0%",
        help="Mean exact-match accuracy across three independent benchmark runs.",
    )

with metric2:
    st.metric(
        label="Mean Audit Latency",
        value="3.11 s",
        help="Mean audit latency across the three benchmark runs.",
    )

with metric3:
    st.metric(
        label="Test Scenarios",
        value="200",
        help="Synthetic benchmark scenarios spanning 20 NIST SP 800-53 Rev. 5 control families.",
    )

with metric4:
    st.metric(
        label="Total Evaluations",
        value="600",
        help="200 scenarios executed independently three times.",
    )

st.caption(
    "200 scenarios × 3 independent runs = 600 evaluations · "
    "20 NIST SP 800-53 Rev. 5 control families · "
    "exact-match status/risk classification"
)

with st.expander("🔬 Benchmark methodology and limitations"):
    st.markdown(
        """
**Benchmark composition**

- 200 synthetic, rubric-aligned security scenarios
- 80 expected `COMPLIANT / LOW`
- 80 expected `PARTIALLY_COMPLIANT / MODERATE`
- 40 expected `NON_COMPLIANT / CRITICAL`
- Scenarios span 20 NIST SP 800-53 Rev. 5 control families
- Three independent executions produced 600 total evaluations

**Observed results**

| Run | Exact-match accuracy |
|---|---:|
| Run 1 | 96.5% |
| Run 2 | 96.0% |
| Run 3 | 95.5% |
| **Mean** | **96.0%** |

The current benchmark evaluates exact agreement between the expected
and generated **overall compliance status and risk classification**.

Critical scenarios remain the most difficult category. Across the
three runs, critical-case exact-match performance was approximately
**80.8% (97/120)**.

The benchmark is synthetic and is intended for controlled research
evaluation. It is not an independent FedRAMP certification dataset.
        """
    )

st.info(
    "Research prototype: results support security and compliance analysis "
    "but do not replace a formal FedRAMP assessment, authorization process, "
    "or independent 3PAO validation."
)

st.divider()


# ============================================================
# Sidebar
# ============================================================

with st.sidebar:
    st.header("⚙️ System Architecture")

    st.markdown(
        """
**Frontend**  
Streamlit Cloud

**Backend**  
AWS Lambda — Serverless

**AI Reasoning**  
LLM-based compliance agent

**Security Standard**  
NIST SP 800-53 Rev. 5

**Federal Baseline**  
FedRAMP High-aligned

**Control Knowledge Base**  
NIST SP 800-53 Rev. 5 catalog
        """
    )

    st.divider()

    st.markdown("### 🧪 Research Benchmark")
    st.markdown(
        """
**200 scenarios · 3 runs · 600 evaluations**

**96.0%** mean exact-match accuracy  
**3.11 s** mean audit latency
        """
    )

    st.divider()

    backend_mode = "AWS Lambda" if get_lambda_url() else "Local fallback"
    st.caption(f"Runtime backend: **{backend_mode}**")

    st.link_button(
        "📂 Source & Benchmark",
        "https://github.com/rapolu-dl/fedramp-compliance-auditor",
        use_container_width=True,
    )


# ============================================================
# Compliance assessment
# ============================================================

st.subheader("🔎 Run a Compliance Assessment")

st.write(
    "Choose a reference architecture or provide a custom cloud security "
    "specification for assessment."
)

if "reference_scenario" not in st.session_state:
    st.session_state["reference_scenario"] = "Compliant — Zero-Trust GovCloud"

if "architecture_spec" not in st.session_state:
    st.session_state["architecture_spec"] = REFERENCE_SCENARIOS[
        st.session_state["reference_scenario"]
    ]

st.selectbox(
    "Reference scenario",
    options=list(REFERENCE_SCENARIOS.keys()),
    key="reference_scenario",
    on_change=load_selected_scenario,
)

with st.form("compliance_assessment_form"):
    st.text_area(
        "Architecture Security Specification",
        key="architecture_spec",
        height=260,
        placeholder=(
            "Describe identity, network exposure, encryption, key management, "
            "logging, monitoring, administrative access, data stores, and other "
            "relevant security controls."
        ),
    )

    submitted = st.form_submit_button(
        "🛡️ Run FedRAMP / NIST Assessment",
        type="primary",
        use_container_width=True,
    )

if submitted:
    architecture = st.session_state.get("architecture_spec", "").strip()

    if not architecture:
        st.warning("Enter an architecture security specification before running the assessment.")
    else:
        try:
            with st.spinner(
                "Evaluating architecture evidence against the compliance reasoning workflow..."
            ):
                audit_result, backend_used = run_audit(architecture)

            st.session_state["last_audit_result"] = audit_result
            st.session_state["last_audit_architecture"] = architecture
            st.session_state["last_backend_used"] = backend_used

        except Exception as exc:
            st.error("The compliance assessment could not be completed.")
            st.exception(exc)


# ============================================================
# Results
# ============================================================

result = st.session_state.get("last_audit_result")

if result:
    architecture = st.session_state.get("last_audit_architecture", "")
    backend_used = st.session_state.get("last_backend_used", "Unknown")

    st.divider()
    st.subheader("📋 Compliance Assessment Result")

    overall_status = str(result.get("overall_status", "UNKNOWN"))
    overall_risk = str(result.get("overall_risk_score", "UNKNOWN"))

    col1, col2, col3 = st.columns([1.2, 1.2, 1])

    with col1:
        st.metric(
            "Compliance Verdict",
            f"{status_icon(overall_status)} {overall_status.replace('_', ' ')}",
        )

    with col2:
        st.metric(
            "Risk Classification",
            f"{risk_icon(overall_risk)} {overall_risk}",
        )

    with col3:
        st.metric(
            "Backend",
            backend_used,
        )

    summary = result.get("ciso_executive_summary")
    if summary:
        st.markdown("### CISO Executive Summary")
        st.info(str(summary))

    tab_findings, tab_controls, tab_remediation, tab_ssp, tab_raw = st.tabs(
        [
            "🔎 Audit Findings",
            "🧩 Violated Controls",
            "🛠️ Remediation",
            "📄 SSP / Report",
            "🧪 Raw JSON",
        ]
    )

    with tab_findings:
        _render_collection(
            result.get("audit_findings"),
            "No audit findings were returned.",
        )

    with tab_controls:
        _render_collection(
            result.get("violated_controls"),
            "No violated controls were returned.",
        )

    with tab_remediation:
        _render_collection(
            result.get("mandated_remediation"),
            "No mandated remediation was returned.",
        )

    with tab_ssp:
        report_markdown = build_markdown_report(result, architecture)

        st.markdown(
            """
The downloadable report captures the architecture specification,
overall verdict, risk classification, findings, violated controls,
remediation, and the CISO executive summary returned by the agent.
            """
        )

        st.download_button(
            label="⬇️ Download Audit / SSP Report (.md)",
            data=report_markdown,
            file_name="fedramp_nist_audit_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

        st.markdown("#### Report Preview")
        st.markdown(report_markdown)

    with tab_raw:
        st.json(result)

    st.caption(
        "Prototype output should be independently reviewed before use in "
        "authorization, audit, or production remediation decisions."
    )
