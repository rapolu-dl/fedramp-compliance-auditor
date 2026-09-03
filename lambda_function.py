import base64
import json
import logging
import os
from typing import Any, Dict

from compliance_agent import audit_system


logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "131072"))

CORS_ALLOW_ORIGIN = os.getenv("CORS_ALLOW_ORIGIN", "*")


def _response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": CORS_ALLOW_ORIGIN,
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        },
        "body": json.dumps(body, ensure_ascii=False),
    }


def _parse_event(event: Any) -> Dict[str, Any]:
    """
    Accepts:
      1. API Gateway / Lambda Function URL events with JSON body
      2. Direct Lambda invocation with {"architecture": "..."}
    """
    if not isinstance(event, dict):
        raise ValueError("Request must be a JSON object.")

    request_context = event.get("requestContext") or {}
    http_context = request_context.get("http") or {}
    method = (
        http_context.get("method")
        or event.get("httpMethod")
        or ""
    ).upper()

    if method == "OPTIONS":
        return {"_options": True}

    # Direct invocation.
    if "architecture" in event and "body" not in event:
        return event

    body = event.get("body")

    if body is None:
        raise ValueError(
            "Missing request body. Expected JSON with an 'architecture' field."
        )

    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body).decode("utf-8")
        except Exception as exc:
            raise ValueError("Invalid base64-encoded request body.") from exc

    if isinstance(body, dict):
        return body

    if not isinstance(body, str):
        raise ValueError("Request body must be JSON.")

    if len(body.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("Request body exceeds the configured size limit.")

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("Request body is not valid JSON.") from exc

    if not isinstance(parsed, dict):
        raise ValueError("Request JSON must be an object.")

    return parsed


def lambda_handler(event, context):
    request_id = getattr(context, "aws_request_id", None)

    try:
        payload = _parse_event(event)

        if payload.get("_options"):
            return _response(200, {"ok": True})

        architecture = payload.get("architecture")

        if not isinstance(architecture, str) or not architecture.strip():
            return _response(
                400,
                {
                    "error": "INVALID_REQUEST",
                    "message": (
                        "Field 'architecture' is required and must be "
                        "a non-empty string."
                    ),
                    "request_id": request_id,
                },
            )

        logger.info(
            "Starting compliance assessment request_id=%s architecture_chars=%d",
            request_id,
            len(architecture),
        )

        report = audit_system(architecture)

        if hasattr(report, "model_dump"):
            result = report.model_dump()
        elif hasattr(report, "dict"):
            result = report.dict()
        else:
            raise RuntimeError("Unexpected report object returned by audit_system().")

        result["request_id"] = request_id

        logger.info(
            "Completed compliance assessment request_id=%s status=%s risk=%s",
            request_id,
            result.get("overall_status"),
            result.get("overall_risk_score"),
        )

        return _response(200, result)

    except ValueError as exc:
        logger.warning(
            "Bad request request_id=%s error=%s",
            request_id,
            exc,
        )
        return _response(
            400,
            {
                "error": "INVALID_REQUEST",
                "message": str(exc),
                "request_id": request_id,
            },
        )

    except Exception:
        logger.exception(
            "Compliance assessment failed request_id=%s",
            request_id,
        )
        return _response(
            500,
            {
                "error": "ASSESSMENT_FAILED",
                "message": "The compliance assessment could not be completed.",
                "request_id": request_id,
            },
        )
