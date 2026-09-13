import json
import re
from datetime import datetime, timezone, timedelta


MAX_DECISION_AGE_HOURS = 24
CLOCK_SKEW_MINUTES = 5


def normalize_key(value):
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        str(value).lower(),
    ).strip("_")


def decode_json(value):
    current = value

    for _ in range(5):
        if not isinstance(current, str):
            break

        text = current.strip()

        if not text or text[0] not in "[{":
            break

        try:
            current = json.loads(text)
        except Exception:
            break

    return current


def find_named_output(root, wanted_name):
    wanted = normalize_key(wanted_name)
    visited = set()

    def walk(value):
        value = decode_json(value)

        if isinstance(value, (dict, list)):
            object_id = id(value)

            if object_id in visited:
                return None

            visited.add(object_id)

        if isinstance(value, dict):
            for key, child in value.items():
                if normalize_key(key) == wanted:
                    return decode_json(child)

            possible_names = [
                value.get("name"),
                value.get("label"),
                value.get("action_name"),
            ]

            action = value.get("action")

            if isinstance(action, dict):
                possible_names.extend([
                    action.get("name"),
                    action.get("label"),
                ])
            elif isinstance(action, str):
                possible_names.append(action)

            if any(
                normalize_key(name) == wanted
                for name in possible_names
                if name
            ):
                for output_key in (
                    "result",
                    "output",
                    "data",
                    "body",
                    "message",
                ):
                    if output_key in value:
                        return decode_json(value[output_key])

                return value

            for child in value.values():
                found = walk(child)

                if found is not None:
                    return found

        elif isinstance(value, list):
            for child in value:
                found = walk(child)

                if found is not None:
                    return found

        return None

    return walk(root)


def find_row(value, marker_fields):
    value = decode_json(value)

    if isinstance(value, dict):
        normalized_keys = {
            normalize_key(key)
            for key in value.keys()
        }

        if any(
            normalize_key(marker) in normalized_keys
            for marker in marker_fields
        ):
            return value

        for key in (
            "message",
            "body",
            "results",
            "result",
            "data",
            "content",
            "output",
        ):
            if key in value:
                found = find_row(value[key], marker_fields)

                if found is not None:
                    return found

        for child in value.values():
            found = find_row(child, marker_fields)

            if found is not None:
                return found

    elif isinstance(value, list):
        for child in value:
            found = find_row(child, marker_fields)

            if found is not None:
                return found

    return None


def find_case_record(value):
    value = decode_json(value)

    if isinstance(value, dict):
        if (
            str(value.get("schema_version", "")).upper()
            == "PB04_CASE_V1"
            and value.get("case_id")
            and value.get("campaign_id")
        ):
            return value

        if "case_record" in value:
            found = find_case_record(value["case_record"])

            if found is not None:
                return found

        for child in value.values():
            found = find_case_record(child)

            if found is not None:
                return found

    elif isinstance(value, list):
        for child in value:
            found = find_case_record(child)

            if found is not None:
                return found

    return None


def to_bool(value):
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in (
        "true",
        "1",
        "yes",
        "enabled",
    )


def ensure_action_list(value):
    value = decode_json(value)

    if value in (None, "", [], {}):
        return []

    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[,;\n]+", str(value))

    normalized = []

    for item in items:
        action = re.sub(
            r"[^A-Z0-9]+",
            "_",
            str(item).strip().upper(),
        ).strip("_")

        if action and action not in normalized:
            normalized.append(action)

    return normalized


def parse_time(value):
    if value in (None, ""):
        return None

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
        except Exception:
            return None

    text = str(value).strip()

    if text.isdigit():
        try:
            return datetime.fromtimestamp(
                float(text),
                tz=timezone.utc,
            )
        except Exception:
            return None

    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


receiver_output = decode_json(
    r'''$receive_pb04_analyst_decision_context'''
)

datastore_output = decode_json(
    r'''$retrieve_persisted_open_pb04_case'''
)

receiver = find_row(
    receiver_output,
    [
        "receiver_valid",
        "analyst_decision",
        "case_record",
    ],
) or {}

datastore = find_row(
    datastore_output,
    [
        "success",
        "found",
        "value",
    ],
) or {}

errors = []

if not to_bool(receiver.get("receiver_valid")):
    errors.append("DECISION_RECEIVER_INVALID")

if not to_bool(datastore.get("success")):
    errors.append("OPEN_CASE_LOOKUP_FAILED")

if not to_bool(datastore.get("found")):
    errors.append("OPEN_CASE_NOT_FOUND")

# The callback may contain a case snapshot, but it is not trusted or
# required. The persisted datastore record is the source of truth.
callback_case = find_case_record(
    receiver.get("case_record", {})
) or {}

persisted_case = find_case_record(
    datastore.get("value", datastore)
)

if persisted_case is None:
    errors.append("PERSISTED_CASE_RECORD_MISSING")
    persisted_case = {}

callback_case_id = str(
    receiver.get("case_id")
    or callback_case.get("case_id")
    or ""
).strip()

persisted_case_id = str(
    persisted_case.get("case_id", "")
).strip()

callback_campaign_id = str(
    receiver.get("campaign_id")
    or callback_case.get("campaign_id")
    or ""
).strip()

persisted_campaign_id = str(
    persisted_case.get("campaign_id", "")
).strip()

if not callback_case_id or (
    callback_case_id != persisted_case_id
):
    errors.append("CASE_ID_MISMATCH")

if not callback_campaign_id or (
    callback_campaign_id != persisted_campaign_id
):
    errors.append("CAMPAIGN_ID_MISMATCH")

callback_version = (
    receiver.get("case_version")
    or callback_case.get("case_version")
)
persisted_version = persisted_case.get(
    "case_version"
)

# Validate a supplied callback version, but do not require the callback
# to carry the full persisted case record.
if (
    callback_version not in (None, "")
    and str(callback_version) != str(persisted_version)
):
    errors.append("CASE_VERSION_MISMATCH")

case_status = str(
    persisted_case.get("case_status", "")
).upper()

valid_open_statuses = {
    "AWAITING_ANALYST_APPROVAL",
    "AWAITING_ANALYST_REVIEW",
}

if case_status not in valid_open_statuses:
    errors.append("CASE_NOT_AWAITING_ANALYST_DECISION")

stored_decision = persisted_case.get(
    "analyst_decision",
    {},
)

stored_decision_status = str(
    stored_decision.get("status", "")
).upper()

if stored_decision_status != "PENDING":
    errors.append("CASE_DECISION_ALREADY_PROCESSED")

decision = str(
    receiver.get("analyst_decision", "")
).upper()

allowed_decisions = {
    str(item).upper()
    for item in stored_decision.get(
        "allowed_decisions",
        [],
    )
}

if decision not in allowed_decisions:
    errors.append(
        "DECISION_NOT_ALLOWED_FOR_PERSISTED_CASE"
    )

analyst_identity = str(
    receiver.get("analyst_identity", "")
).strip()

if not analyst_identity:
    errors.append("ANALYST_IDENTITY_MISSING")

approved_actions_requested = ensure_action_list(
    receiver.get("approved_actions_requested")
)

persisted_executable_actions = ensure_action_list(
    persisted_case.get(
        "response",
        {},
    ).get(
        "executable_actions_after_approval",
        [],
    )
)

approval_decisions = {
    "APPROVE_ALL_PROPOSED_ACTIONS",
    "APPROVE_LIMITED",
}

if decision in approval_decisions:
    if case_status != "AWAITING_ANALYST_APPROVAL":
        errors.append(
            "CASE_DOES_NOT_ALLOW_ACTION_APPROVAL"
        )

    if not approved_actions_requested:
        errors.append("APPROVAL_CONTAINS_NO_ACTIONS")

    unauthorized_actions = [
        action
        for action in approved_actions_requested
        if action not in persisted_executable_actions
    ]

    if unauthorized_actions:
        errors.append(
            "APPROVAL_CONTAINS_UNAUTHORIZED_ACTIONS"
        )
else:
    # A non-approval decision must never carry executable actions.
    approved_actions_requested = []

now_utc = datetime.now(timezone.utc)

case_reference_time = parse_time(
    persisted_case.get("updated_at")
    or persisted_case.get("created_at")
)

if case_reference_time is None:
    errors.append("PERSISTED_CASE_TIMESTAMP_INVALID")
else:
    if case_reference_time > (
        now_utc + timedelta(minutes=CLOCK_SKEW_MINUTES)
    ):
        errors.append("PERSISTED_CASE_TIMESTAMP_IN_FUTURE")

    if now_utc - case_reference_time > timedelta(
        hours=MAX_DECISION_AGE_HOURS
    ):
        errors.append("ANALYST_DECISION_EXPIRED")

decision_time = parse_time(
    receiver.get("analyst_decision_time")
)

if decision_time is None:
    errors.append("ANALYST_DECISION_TIME_INVALID")
else:
    if decision_time > (
        now_utc + timedelta(minutes=CLOCK_SKEW_MINUTES)
    ):
        errors.append("DECISION_TIME_IN_FUTURE")

    created_time = parse_time(
        persisted_case.get("created_at")
    )

    if (
        created_time is not None
        and decision_time
        < created_time
        - timedelta(minutes=CLOCK_SKEW_MINUTES)
    ):
        errors.append("DECISION_PREDATES_CASE")

validation_valid = len(errors) == 0

if decision in approval_decisions:
    decision_route = "EXECUTE_APPROVED_ACTIONS"
elif decision == "REJECT":
    decision_route = "FINALIZE_REJECTED"
elif decision == "FALSE_POSITIVE":
    decision_route = "FINALIZE_FALSE_POSITIVE"
elif decision == "ESCALATE":
    decision_route = "FINALIZE_ESCALATED"
elif decision == "ACKNOWLEDGE_AND_MONITOR":
    decision_route = "FINALIZE_MONITORING"
elif decision == "CLOSE_NO_ACTION":
    decision_route = "FINALIZE_NO_ACTION"
else:
    decision_route = "FAILED_CLOSED"

if not validation_valid:
    decision_route = "FAILED_CLOSED"

decision_authorizes_identity_action = (
    validation_valid
    and decision in approval_decisions
    and len(approved_actions_requested) > 0
)

decision_record = {
    "decision": decision,
    "analyst_identity": analyst_identity,
    "decision_time": receiver.get(
        "analyst_decision_time",
        "",
    ),
    "analyst_note": receiver.get(
        "analyst_note",
        "",
    ),
    "approved_actions": (
        approved_actions_requested
        if validation_valid
        else []
    ),
    "validation_status": (
        "VALID"
        if validation_valid
        else "INVALID"
    ),
}

output = {
    "decision_validation_valid": validation_valid,
    "decision_validation_status": (
        "ANALYST_DECISION_VALIDATED"
        if validation_valid
        else "FAILED_CLOSED"
    ),
    "decision_validation_errors": errors,

    "playbook_id": persisted_case.get(
        "playbook_id",
        "PB04",
    ),
    "case_id": persisted_case_id,
    "campaign_id": persisted_campaign_id,
    "case_version": persisted_version,
    "case_status": case_status,

    "analyst_decision": decision,
    "analyst_identity": analyst_identity,
    "analyst_decision_time": receiver.get(
        "analyst_decision_time",
        "",
    ),
    "analyst_note": receiver.get(
        "analyst_note",
        "",
    ),

    "approved_actions_validated": (
        approved_actions_requested
        if validation_valid
        else []
    ),
    "persisted_executable_actions": (
        persisted_executable_actions
    ),
    "decision_authorizes_identity_action": (
        decision_authorizes_identity_action
    ),
    "decision_is_non_execution": (
        validation_valid
        and not decision_authorizes_identity_action
    ),
    "decision_route": decision_route,
    "decision_record": decision_record,

    "persisted_case_record": persisted_case,
    "case_age_policy_hours": MAX_DECISION_AGE_HOURS,

    "identity_action_authorized": (
        decision_authorizes_identity_action
    ),
    "safety_revalidation_passed": False,
    "automated_response_allowed": False,
}

print(json.dumps(output))
