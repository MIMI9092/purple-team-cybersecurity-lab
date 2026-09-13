import ast
import json
from datetime import datetime, timezone


def decode_json(value):
    current = value

    for _ in range(6):
        if isinstance(current, (dict, list)):
            return current

        if current is None:
            return {}

        if isinstance(current, bytes):
            current = current.decode("utf-8", errors="replace")
            continue

        if not isinstance(current, str):
            return current

        text = current.strip()
        if not text:
            return {}

        try:
            current = json.loads(text)
            continue
        except Exception:
            pass

        try:
            current = ast.literal_eval(text)
            continue
        except Exception:
            return {}

    return current


def as_bool(value):
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value != 0

    return str(value).strip().lower() in (
        "true",
        "1",
        "yes",
        "y",
        "on",
    )


def find_investigation_context(value):
    value = decode_json(value)

    if isinstance(value, dict):
        if (
            str(value.get("playbook_id", "")).strip().upper() == "PB05"
            and str(value.get("case_id", "")).strip().startswith("PB05-CASE-")
            and (
                "normalization_valid" in value
                or "normalization_status" in value
                or "detection_id" in value
            )
        ):
            return value

        preferred_keys = (
            "message",
            "result",
            "body",
            "data",
            "value",
            "payload",
        )

        for key in preferred_keys:
            if key in value:
                found = find_investigation_context(value.get(key))
                if found:
                    return found

        for nested_value in value.values():
            found = find_investigation_context(nested_value)
            if found:
                return found

    elif isinstance(value, list):
        for item in value:
            found = find_investigation_context(item)
            if found:
                return found

    return {}


raw_input = r'''$exec'''
decoded_input = decode_json(raw_input)
context = find_investigation_context(decoded_input)

errors = []

if not isinstance(context, dict) or not context:
    context = {}
    errors.append("PB05_INVESTIGATION_CONTEXT_NOT_FOUND")

playbook_id = str(context.get("playbook_id", "")).strip().upper()
schema_version = str(context.get("schema_version", "")).strip()
case_id = str(context.get("case_id", "")).strip()
campaign_id = str(context.get("campaign_id", "")).strip()
case_lookup_key = str(context.get("case_lookup_key", "")).strip()
detection_id = str(context.get("detection_id", "")).strip().upper()
endpoint_host = str(context.get("endpoint_host", "")).strip()
affected_user = str(context.get("affected_user", "")).strip()

if playbook_id != "PB05":
    errors.append("INVALID_PLAYBOOK_ID")

if schema_version != "PB05-1.0":
    errors.append("INVALID_SCHEMA_VERSION")

if not case_id.startswith("PB05-CASE-"):
    errors.append("INVALID_CASE_ID")

if not campaign_id.startswith("PB05-CMP-"):
    errors.append("INVALID_CAMPAIGN_ID")

if not case_lookup_key:
    errors.append("CASE_LOOKUP_KEY_MISSING")
elif campaign_id and case_lookup_key != campaign_id:
    errors.append("CASE_LOOKUP_KEY_MISMATCH")

if detection_id not in ("D17", "D18"):
    errors.append("UNSUPPORTED_DETECTION_ID")

if not as_bool(context.get("normalization_valid", False)):
    errors.append("NORMALIZATION_NOT_VALID")

if not as_bool(context.get("supported_alert", False)):
    errors.append("ALERT_NOT_SUPPORTED")

if as_bool(context.get("fail_closed", False)):
    errors.append("UPSTREAM_CONTEXT_FAILED_CLOSED")

if not endpoint_host:
    errors.append("ENDPOINT_HOST_MISSING")

if not affected_user:
    errors.append("AFFECTED_USER_MISSING")

receiver_valid = len(errors) == 0
output = dict(context)

output["receiver_status"] = (
    "RECEIVED" if receiver_valid else "FAILED_CLOSED"
)
output["investigation_phase"] = (
    "CONTEXT_RECEIVED" if receiver_valid else "CONTEXT_REJECTED"
)
output["receiver_valid"] = receiver_valid
output["receiver_errors"] = errors
output["investigation_received_at"] = datetime.now(timezone.utc).isoformat().replace(
    "+00:00", "Z"
)

if not receiver_valid:
    output["fail_closed"] = True
    output["automated_response_allowed"] = False

print(json.dumps(output, ensure_ascii=False))
