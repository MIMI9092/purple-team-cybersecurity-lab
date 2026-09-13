import json
import re
from datetime import datetime, timezone


def decode_json(value):
    current = value

    for _ in range(5):
        if isinstance(current, (dict, list)):
            return current

        if current is None:
            return {}

        if not isinstance(current, str):
            return current

        text = current.strip()

        if not text:
            return {}

        try:
            current = json.loads(text)
        except Exception:
            return current

    return current


def normalize_token(value):
    return re.sub(
        r"[^A-Z0-9]+",
        "_",
        str(value or "").strip().upper()
    ).strip("_")


def normalize_actions(value):
    parsed = decode_json(value)

    if isinstance(parsed, list):
        items = parsed
    elif isinstance(parsed, str):
        items = re.split(r"[,;\n]+", parsed)
    elif parsed in (None, ""):
        items = []
    else:
        items = [parsed]

    actions = []

    for item in items:
        action = normalize_token(item)

        if action and action not in actions:
            actions.append(action)

    return actions


def find_decision_payload(value):
    parsed = decode_json(value)

    if isinstance(parsed, dict):
        decision_keys = {
            "decision",
            "analyst_decision",
            "decision_id",
            "case_id",
            "campaign_id"
        }

        if decision_keys.intersection(parsed.keys()):
            return parsed

        for key in (
            "message",
            "result",
            "body",
            "data",
            "value",
            "execution_argument",
            "$" + "exec"
        ):
            if key in parsed:
                candidate = find_decision_payload(parsed.get(key))

                if candidate:
                    return candidate

    return {}


received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

raw_input = r'''$exec'''
payload = find_decision_payload(raw_input)

schema_version = str(
    payload.get("schema_version")
    or "PB05_DECISION_V1"
).strip()

playbook_id = normalize_token(
    payload.get("playbook_id")
    or "PB05"
)

decision_id = str(
    payload.get("decision_id")
    or ""
).strip()

case_id = str(
    payload.get("case_id")
    or ""
).strip()

campaign_id = str(
    payload.get("campaign_id")
    or ""
).strip()

case_lookup_key = str(
    payload.get("case_lookup_key")
    or campaign_id
).strip()

case_status = normalize_token(
    payload.get("case_status")
)

analyst_decision = normalize_token(
    payload.get("analyst_decision")
    or payload.get("decision")
)

analyst_identity = str(
    payload.get("analyst_identity")
    or payload.get("analyst")
    or ""
).strip()

analyst_decision_time = str(
    payload.get("decision_time")
    or payload.get("analyst_decision_time")
    or ""
).strip()

analyst_note = str(
    payload.get("analyst_comment")
    or payload.get("analyst_note")
    or payload.get("comment")
    or ""
).strip()

decision_source = normalize_token(
    payload.get("decision_source")
    or "MANUAL_ANALYST_INPUT"
)

approved_actions_requested = normalize_actions(
    payload.get("approved_actions")
    or payload.get("approved_actions_requested")
)

case_executable_actions = normalize_actions(
    payload.get("case_executable_actions")
    or payload.get("executable_actions_after_approval")
)

case_record = decode_json(
    payload.get("case_record")
)

if not isinstance(case_record, dict):
    case_record = {}

allowed_decisions = {
    "ACKNOWLEDGE_AND_MONITOR",
    "APPROVE_ALL_PROPOSED_ACTIONS",
    "APPROVE_LIMITED",
    "REJECT",
    "FALSE_POSITIVE",
    "ESCALATE"
}

errors = []

if schema_version != "PB05_DECISION_V1":
    errors.append("UNSUPPORTED_DECISION_SCHEMA")

if playbook_id != "PB05":
    errors.append("INVALID_PLAYBOOK_ID")

if not decision_id:
    errors.append("MISSING_DECISION_ID")

if not case_id.startswith("PB05-CASE-"):
    errors.append("INVALID_CASE_ID")

if not campaign_id.startswith("PB05-CMP-"):
    errors.append("INVALID_CAMPAIGN_ID")

if not case_lookup_key:
    errors.append("MISSING_CASE_LOOKUP_KEY")

if analyst_decision not in allowed_decisions:
    errors.append("UNSUPPORTED_ANALYST_DECISION")

if not analyst_identity:
    errors.append("MISSING_ANALYST_IDENTITY")

if not analyst_decision_time:
    errors.append("MISSING_ANALYST_DECISION_TIME")

receiver_valid = len(errors) == 0

output = {
    "receiver_valid": receiver_valid,
    "receiver_status": (
        "PB05_ANALYST_DECISION_RECEIVED"
        if receiver_valid
        else "PB05_ANALYST_DECISION_REJECTED"
    ),
    "receiver_errors": errors,
    "schema_version": schema_version,
    "playbook_id": playbook_id,
    "decision_id": decision_id,
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": case_lookup_key,
    "case_status": case_status,
    "analyst_decision": analyst_decision,
    "analyst_identity": analyst_identity,
    "analyst_decision_time": analyst_decision_time,
    "analyst_note": analyst_note,
    "decision_source": decision_source,
    "approved_actions_requested": approved_actions_requested,
    "case_executable_actions": case_executable_actions,
    "case_record": case_record,
    "approval_valid": False,
    "endpoint_action_authorized": False,
    "network_action_authorized": False,
    "automated_response_allowed": False,
    "received_at": received_at
}

print(json.dumps(output))
