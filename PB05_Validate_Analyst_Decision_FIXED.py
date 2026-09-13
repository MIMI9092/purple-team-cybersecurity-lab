import json
import re
from datetime import datetime, timezone

MAX_CASE_AGE_HOURS = 24
MAX_DECISION_AGE_MINUTES = 60
MAX_FUTURE_SKEW_MINUTES = 5

ACTION_ALIASES = {
    "BLOCK_VALIDATED_C2_DESTINATION": "BLOCK_C2_DESTINATION",
    "TERMINATE_MATCHING_PF_STATE": "TERMINATE_MATCHING_PF_STATES",
    "STOP_VERIFIED_TUNNEL_PROCESS": "STOP_VERIFIED_PROCESS",
    "REMOVE_EXACT_RUN_VALUE": "REMOVE_VERIFIED_RUN_VALUE",
}


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
        action = ACTION_ALIASES.get(action, action)

        if action and action not in actions:
            actions.append(action)

    return actions


def find_first_key(value, candidate_keys):
    parsed = decode_json(value)

    if isinstance(parsed, dict):
        for key in candidate_keys:
            if key in parsed and parsed.get(key) not in (None, "", [], {}):
                return parsed.get(key)

        for child in parsed.values():
            found = find_first_key(child, candidate_keys)

            if found not in (None, "", [], {}):
                return found

    elif isinstance(parsed, list):
        for child in parsed:
            found = find_first_key(child, candidate_keys)

            if found not in (None, "", [], {}):
                return found

    return None


def parse_timestamp(value):
    text = str(value or "").strip()

    if not text:
        return None

    candidates = [
        text,
        text.replace("Z", "+00:00"),
        text.replace(" ", "T").replace("Z", "+00:00")
    ]

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(timezone.utc)
        except Exception:
            pass

    for timestamp_format in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f"
    ):
        try:
            return datetime.strptime(
                text,
                timestamp_format
            ).replace(tzinfo=timezone.utc)
        except Exception:
            pass

    return None


receiver_wrapper = decode_json(
    r'''$receive_pb05_analyst_decision_context'''
)

receiver = receiver_wrapper.get(
    "message",
    receiver_wrapper
) if isinstance(receiver_wrapper, dict) else {}

datastore = decode_json(
    r'''$retrieve_persisted_open_pb05_case'''
)

if not isinstance(receiver, dict):
    receiver = {}

if not isinstance(datastore, dict):
    datastore = {}

persisted_case = decode_json(
    datastore.get("value")
)

if not isinstance(persisted_case, dict):
    persisted_case = {}

now = datetime.now(timezone.utc)

errors = []

receiver_valid = receiver.get("receiver_valid") is True
datastore_success = datastore.get("success") is True
case_found = datastore.get("found") is True and bool(persisted_case)

playbook_id = normalize_token(
    receiver.get("playbook_id")
)

decision_id = str(
    receiver.get("decision_id")
    or ""
).strip()

case_id = str(
    receiver.get("case_id")
    or ""
).strip()

campaign_id = str(
    receiver.get("campaign_id")
    or ""
).strip()

case_lookup_key = str(
    receiver.get("case_lookup_key")
    or campaign_id
).strip()

analyst_decision = normalize_token(
    receiver.get("analyst_decision")
)

analyst_identity = str(
    receiver.get("analyst_identity")
    or ""
).strip()

analyst_decision_time = str(
    receiver.get("analyst_decision_time")
    or ""
).strip()

analyst_note = str(
    receiver.get("analyst_note")
    or ""
).strip()

decision_source = normalize_token(
    receiver.get("decision_source")
)

requested_actions = normalize_actions(
    receiver.get("approved_actions_requested")
)

persisted_playbook_id = normalize_token(
    persisted_case.get("playbook_id")
    or find_first_key(persisted_case, {"playbook_id"})
)

persisted_case_id = str(
    persisted_case.get("case_id")
    or find_first_key(persisted_case, {"case_id"})
    or ""
).strip()

persisted_campaign_id = str(
    persisted_case.get("campaign_id")
    or find_first_key(persisted_case, {"campaign_id"})
    or ""
).strip()

persisted_lookup_key = str(
    persisted_case.get("case_lookup_key")
    or persisted_campaign_id
).strip()

case_version_raw = (
    persisted_case.get("case_version")
    or find_first_key(persisted_case, {"case_version"})
    or 1
)

try:
    case_version = int(case_version_raw)
except Exception:
    case_version = 1

case_status = normalize_token(
    persisted_case.get("case_status")
    or persisted_case.get("status")
    or find_first_key(
        persisted_case,
        {"case_status"}
    )
)

response_profile = normalize_token(
    persisted_case.get("response_profile")
    or find_first_key(
        persisted_case,
        {"response_profile", "profile"}
    )
)

persisted_executable_actions = normalize_actions(
    persisted_case.get("executable_actions_after_approval")
    or find_first_key(
        persisted_case,
        {
            "executable_actions_after_approval",
            "persisted_executable_actions"
        }
    )
)

persisted_allowed_decisions = normalize_actions(
    persisted_case.get("allowed_decisions")
    or find_first_key(
        persisted_case,
        {"allowed_decisions"}
    )
)

authorization_status = normalize_token(
    find_first_key(
        persisted_case,
        {"authorization_status"}
    )
)

case_timestamp_text = str(
    persisted_case.get("updated_at")
    or persisted_case.get("created_at")
    or find_first_key(
        persisted_case,
        {
            "updated_at",
            "created_at",
            "case_updated_at",
            "case_created_at",
            "built_at"
        }
    )
    or ""
).strip()

case_timestamp = parse_timestamp(case_timestamp_text)
decision_timestamp = parse_timestamp(analyst_decision_time)

if not receiver_valid:
    errors.append("INVALID_DECISION_RECEIVER_CONTEXT")

if not datastore_success:
    errors.append("DATASTORE_RETRIEVAL_FAILED")

if not case_found:
    errors.append("PERSISTED_OPEN_CASE_NOT_FOUND")

if playbook_id != "PB05":
    errors.append("INVALID_DECISION_PLAYBOOK")

if persisted_playbook_id and persisted_playbook_id != "PB05":
    errors.append("INVALID_PERSISTED_CASE_PLAYBOOK")

if case_id != persisted_case_id:
    errors.append("CASE_ID_MISMATCH")

if campaign_id != persisted_campaign_id:
    errors.append("CAMPAIGN_ID_MISMATCH")

if (
    persisted_lookup_key
    and case_lookup_key != persisted_lookup_key
):
    errors.append("CASE_LOOKUP_KEY_MISMATCH")

if case_status not in {
    "AWAITING_ANALYST_REVIEW",
    "AWAITING_ANALYST_APPROVAL",
    "AWAITING_ANALYST_ESCALATION",
    "AWAITING_ESCALATION"
}:
    errors.append("CASE_NOT_OPEN_FOR_ANALYST_DECISION")

if response_profile not in {
    "CRP1",
    "CRP2",
    "CRP3",
    "CRP4"
}:
    errors.append("INVALID_OR_UNSUPPORTED_RESPONSE_PROFILE")

if authorization_status == "AUTHORIZED_IN_SCOPE":
    errors.append("AUTHORIZED_TEST_CASE_CANNOT_EXECUTE_RESPONSE")

if not persisted_allowed_decisions:
    errors.append("PERSISTED_ALLOWED_DECISIONS_MISSING")
elif analyst_decision not in persisted_allowed_decisions:
    errors.append("DECISION_NOT_ALLOWED_FOR_CASE")

if case_timestamp is None:
    errors.append("INVALID_OR_MISSING_CASE_TIMESTAMP")
else:
    case_age_seconds = (now - case_timestamp).total_seconds()

    if case_age_seconds < -300:
        errors.append("CASE_TIMESTAMP_IS_IN_THE_FUTURE")
    elif case_age_seconds > MAX_CASE_AGE_HOURS * 3600:
        errors.append("PERSISTED_CASE_EXPIRED")

if decision_timestamp is None:
    errors.append("INVALID_OR_MISSING_DECISION_TIMESTAMP")
else:
    decision_age_seconds = (now - decision_timestamp).total_seconds()

    if decision_age_seconds < -(MAX_FUTURE_SKEW_MINUTES * 60):
        errors.append("DECISION_TIMESTAMP_IS_IN_THE_FUTURE")
    elif decision_age_seconds > MAX_DECISION_AGE_MINUTES * 60:
        errors.append("ANALYST_DECISION_EXPIRED")

allowed_executable_actions = {
    "BLOCK_C2_DESTINATION",
    "TERMINATE_MATCHING_PF_STATES",
    "STOP_VERIFIED_PROCESS",
    "REMOVE_VERIFIED_RUN_VALUE"
}

unknown_persisted_actions = [
    action
    for action in persisted_executable_actions
    if action not in allowed_executable_actions
]

if unknown_persisted_actions:
    errors.append("PERSISTED_CASE_CONTAINS_UNSUPPORTED_ACTION")

approval_decisions = {
    "APPROVE_ALL_PROPOSED_ACTIONS",
    "APPROVE_LIMITED"
}

non_execution_decisions = {
    "ACKNOWLEDGE_AND_MONITOR",
    "REJECT",
    "FALSE_POSITIVE",
    "ESCALATE"
}

approved_actions_validated = []

if analyst_decision == "APPROVE_ALL_PROPOSED_ACTIONS":
    if case_status != "AWAITING_ANALYST_APPROVAL":
        errors.append("CASE_NOT_AWAITING_ACTION_APPROVAL")

    if response_profile not in {"CRP2", "CRP3", "CRP4"}:
        errors.append("RESPONSE_PROFILE_DOES_NOT_ALLOW_EXECUTION")

    if not persisted_executable_actions:
        errors.append("NO_PERSISTED_EXECUTABLE_ACTIONS")

    if requested_actions:
        if set(requested_actions) != set(persisted_executable_actions):
            errors.append("APPROVE_ALL_ACTION_SET_MISMATCH")

    approved_actions_validated = list(persisted_executable_actions)

elif analyst_decision == "APPROVE_LIMITED":
    if case_status != "AWAITING_ANALYST_APPROVAL":
        errors.append("CASE_NOT_AWAITING_ACTION_APPROVAL")

    if response_profile not in {"CRP2", "CRP3", "CRP4"}:
        errors.append("RESPONSE_PROFILE_DOES_NOT_ALLOW_EXECUTION")

    if not requested_actions:
        errors.append("LIMITED_APPROVAL_REQUIRES_ACTIONS")

    unsupported_requested_actions = [
        action
        for action in requested_actions
        if action not in persisted_executable_actions
    ]

    if unsupported_requested_actions:
        errors.append("LIMITED_APPROVAL_CONTAINS_UNAUTHORIZED_ACTION")

    approved_actions_validated = [
        action
        for action in requested_actions
        if action in persisted_executable_actions
    ]

elif analyst_decision in non_execution_decisions:
    if requested_actions:
        errors.append("NON_EXECUTION_DECISION_CONTAINS_ACTIONS")

else:
    errors.append("UNSUPPORTED_DECISION_ROUTE")

decision_authorizes_endpoint_action = any(
    action in {
        "STOP_VERIFIED_PROCESS",
        "REMOVE_VERIFIED_RUN_VALUE"
    }
    for action in approved_actions_validated
)

decision_authorizes_network_action = any(
    action in {
        "BLOCK_C2_DESTINATION",
        "TERMINATE_MATCHING_PF_STATES"
    }
    for action in approved_actions_validated
)

decision_is_non_execution = (
    analyst_decision in non_execution_decisions
    and not approved_actions_validated
)

decision_validation_valid = len(errors) == 0

if not decision_validation_valid:
    decision_route = "FAILED_CLOSED"
elif analyst_decision in approval_decisions:
    decision_route = "REVALIDATE_AND_EXECUTE_APPROVED_ACTIONS"
elif analyst_decision == "ACKNOWLEDGE_AND_MONITOR":
    decision_route = "FINALIZE_MONITORING"
elif analyst_decision == "REJECT":
    decision_route = "FINALIZE_REJECTED"
elif analyst_decision == "FALSE_POSITIVE":
    decision_route = "FINALIZE_FALSE_POSITIVE"
elif analyst_decision == "ESCALATE":
    decision_route = "FINALIZE_ESCALATED"
else:
    decision_route = "FAILED_CLOSED"

decision_record = {
    "decision_id": decision_id,
    "decision": analyst_decision,
    "analyst_identity": analyst_identity,
    "decision_time": analyst_decision_time,
    "analyst_note": analyst_note,
    "decision_source": decision_source,
    "approved_actions": (
        approved_actions_validated
        if decision_validation_valid
        else []
    ),
    "validation_status": (
        "VALID"
        if decision_validation_valid
        else "INVALID"
    )
}

output = {
    "decision_validation_valid": decision_validation_valid,
    "decision_validation_status": (
        "ANALYST_DECISION_VALIDATED"
        if decision_validation_valid
        else "FAILED_CLOSED"
    ),
    "decision_validation_errors": errors,
    "playbook_id": "PB05",
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": case_lookup_key,
    "case_version": case_version,
    "case_status": case_status,
    "response_profile": response_profile,
    "analyst_decision": analyst_decision,
    "analyst_identity": analyst_identity,
    "analyst_decision_time": analyst_decision_time,
    "analyst_note": analyst_note,
    "approved_actions_validated": (
        approved_actions_validated
        if decision_validation_valid
        else []
    ),
    "persisted_executable_actions": persisted_executable_actions,
    "decision_authorizes_endpoint_action": (
        decision_authorizes_endpoint_action
        if decision_validation_valid
        else False
    ),
    "decision_authorizes_network_action": (
        decision_authorizes_network_action
        if decision_validation_valid
        else False
    ),
    "decision_is_non_execution": (
        decision_is_non_execution
        if decision_validation_valid
        else False
    ),
    "decision_route": decision_route,
    "decision_record": decision_record,
    "persisted_case_record": persisted_case,
    "case_age_policy_hours": MAX_CASE_AGE_HOURS,
    "decision_age_policy_minutes": MAX_DECISION_AGE_MINUTES,
    "safety_revalidation_passed": False,
    "endpoint_action_authorized": False,
    "network_action_authorized": False,
    "automated_response_allowed": False
}

print(json.dumps(output))
