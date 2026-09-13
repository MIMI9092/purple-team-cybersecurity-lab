import json
import re
from datetime import datetime, timezone


def decode_json(value):
    current = value
    for _ in range(6):
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


def normalize_actions(value):
    parsed = decode_json(value)
    if isinstance(parsed, list):
        source = parsed
    elif isinstance(parsed, str):
        source = re.split(r"[,;\n]+", parsed)
    else:
        source = []

    actions = []
    for item in source:
        token = re.sub(r"[^A-Z0-9]+", "_", str(item).upper()).strip("_")
        if token and token not in actions:
            actions.append(token)
    return actions


def find_actor(value):
    value = decode_json(value)
    actor_keys = {
        "analyst_identity",
        "approved_by",
        "approver",
        "username",
        "user_name",
        "email"
    }

    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in actor_keys and child not in (None, "", [], {}):
                parsed = decode_json(child)
                if not isinstance(parsed, (dict, list)):
                    return str(parsed).strip()
        for child in value.values():
            actor = find_actor(child)
            if actor:
                return actor

    if isinstance(value, list):
        for child in value:
            actor = find_actor(child)
            if actor:
                return actor

    return ""


def find_click_info(value):
    value = decode_json(value)

    if isinstance(value, dict):
        candidate = decode_json(value.get("click_info"))
        if isinstance(candidate, dict) and candidate:
            return candidate
        for child in value.values():
            candidate = find_click_info(child)
            if candidate:
                return candidate

    if isinstance(value, list):
        for child in value:
            candidate = find_click_info(child)
            if candidate:
                return candidate

    return {}


case_id = str(r'''$build_pb05_analyst_case.message.case_id''').strip()
campaign_id = str(r'''$build_pb05_analyst_case.message.campaign_id''').strip()
case_lookup_key = str(
    r'''$build_pb05_analyst_case.message.case_lookup_key'''
).strip()
case_version_raw = str(
    r'''$build_pb05_analyst_case.message.case_version'''
).strip()
case_status = str(
    r'''$build_pb05_analyst_case.message.case_status'''
).strip().upper()
response_profile = str(
    r'''$build_pb05_analyst_case.message.response_profile'''
).strip().upper()
approved_actions = normalize_actions(
    r'''$build_pb05_analyst_case.message.executable_actions_after_approval'''
)
user_input_result = decode_json(r'''$pb05_analyst_approval''')
click_info = find_click_info(user_input_result)

try:
    case_version = int(case_version_raw)
except Exception:
    case_version = 0

analyst_identity = str(click_info.get("user", "")).strip()
if not analyst_identity:
    analyst_identity = find_actor(user_input_result)
if not analyst_identity:
    # Native User Input proves that its one-time approval link was used, but some
    # Shuffle versions do not return the signed-in user's name to the workflow.
    analyst_identity = "SHUFFLE_USER_INPUT_APPROVER"

errors = []
if not case_id or not case_id.startswith("PB05-CASE-"):
    errors.append("INVALID_OR_MISSING_CASE_ID")
if not campaign_id or not campaign_id.startswith("PB05-CMP-"):
    errors.append("INVALID_OR_MISSING_CAMPAIGN_ID")
if not case_lookup_key or case_lookup_key != campaign_id:
    errors.append("CASE_LOOKUP_KEY_MISMATCH")
if case_version < 1:
    errors.append("INVALID_CASE_VERSION")
if case_status != "AWAITING_ANALYST_APPROVAL":
    errors.append("CASE_NOT_AWAITING_ANALYST_APPROVAL")
if response_profile not in {"CRP2", "CRP3", "CRP4"}:
    errors.append("RESPONSE_PROFILE_DOES_NOT_ALLOW_EXECUTION")
if not approved_actions:
    errors.append("NO_EXECUTABLE_ACTIONS_IN_ANALYST_CASE")

now = datetime.now(timezone.utc)
try:
    click_timestamp = float(click_info.get("time"))
    approval_time = datetime.fromtimestamp(click_timestamp, timezone.utc)
except Exception:
    approval_time = now

decision_time = approval_time.isoformat(timespec="seconds").replace("+00:00", "Z")
case_token = case_id.replace("PB05-CASE-", "", 1) or "UNKNOWN"
decision_id = "PB05-DEC-{}-UI{}".format(
    case_token,
    now.strftime("%Y%m%d%H%M%S")
)

output = {
    "decision_build_valid": len(errors) == 0,
    "decision_build_status": (
        "PB05_APPROVED_DECISION_BUILT" if not errors else "FAILED_CLOSED"
    ),
    "decision_build_errors": errors,
    "schema_version": "PB05_DECISION_V1",
    "playbook_id": "PB05",
    "decision_id": decision_id,
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": case_lookup_key,
    "case_version": case_version,
    "analyst_decision": "APPROVE_ALL_PROPOSED_ACTIONS",
    "decision": "APPROVE_ALL_PROPOSED_ACTIONS",
    "approved_actions": approved_actions if not errors else [],
    "analyst_identity": analyst_identity,
    "decision_time": decision_time,
    "decision_source": "SHUFFLE_NATIVE_USER_INPUT",
    "approval_click_ip": str(click_info.get("ip", "")).strip(),
    "approval_click_time": decision_time,
    "analyst_comment": (
        "Approved through Shuffle User Input after review of the persisted "
        "PB05 case and its exact proposed action set."
    ),
    "response_profile": response_profile,
    "automated_response_allowed": False
}

print(json.dumps(output))
