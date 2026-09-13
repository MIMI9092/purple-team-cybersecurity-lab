import json
import re
from datetime import datetime, timezone


def decode_json(value):
    current = value

    for _ in range(6):
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


def normalize_decision(value):
    normalized = re.sub(
        r"[^A-Z0-9]+",
        "_",
        str(value or "").strip().upper(),
    ).strip("_")

    aliases = {
        "APPROVE": "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVED": "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVE_ALL": "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVE_ALL_ACTIONS": "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVE_ALL_PROPOSED_ACTIONS": "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVE_LIMITED": "APPROVE_LIMITED",
        "APPROVE_LIMITED_ACTIONS": "APPROVE_LIMITED",
        "REJECT": "REJECT",
        "REJECTED": "REJECT",
        "DECLINE": "REJECT",
        "DECLINED": "REJECT",
        "DENY": "REJECT",
        "DENIED": "REJECT",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
        "ESCALATE": "ESCALATE",
        "ACKNOWLEDGE": "ACKNOWLEDGE_AND_MONITOR",
        "ACKNOWLEDGED": "ACKNOWLEDGE_AND_MONITOR",
        "ACKNOWLEDGE_AND_MONITOR": "ACKNOWLEDGE_AND_MONITOR",
        "CLOSE": "CLOSE_NO_ACTION",
        "CLOSE_NO_ACTION": "CLOSE_NO_ACTION",
    }

    return aliases.get(normalized, normalized)


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


def find_nonempty_field(value, wanted_keys):
    value = decode_json(value)

    if isinstance(value, dict):
        for key in wanted_keys:
            if key in value:
                candidate = decode_json(value[key])

                if candidate not in (None, "", [], {}):
                    return candidate

        for key, child in value.items():
            if key == "case_record":
                continue

            found = find_nonempty_field(
                child,
                wanted_keys,
            )

            if found not in (None, "", [], {}):
                return found

    elif isinstance(value, list):
        for child in value:
            found = find_nonempty_field(
                child,
                wanted_keys,
            )

            if found not in (None, "", [], {}):
                return found

    return None


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


payload = decode_json(r'''$exec''')

if not isinstance(payload, dict):
    payload = {}

optional_case_record = find_case_record(payload) or {}
errors = []

case_id = str(
    find_nonempty_field(payload, ["case_id"])
    or optional_case_record.get("case_id", "")
).strip()

campaign_id = str(
    find_nonempty_field(
        payload,
        ["campaign_id", "case_lookup_key"],
    )
    or optional_case_record.get("campaign_id", "")
).strip()

if not case_id:
    errors.append("CASE_ID_MISSING")

if not campaign_id:
    errors.append("CAMPAIGN_ID_MISSING")

raw_decision = find_nonempty_field(
    payload,
    [
        "returned_decision",
        "approval_decision",
        "selected_decision",
        "decision",
        "analyst_decision_result",
        "analyst_decision",
    ],
)

if isinstance(raw_decision, dict):
    raw_decision = (
        raw_decision.get("decision")
        or raw_decision.get("selected_decision")
        or raw_decision.get("status")
        or ""
    )

decision = normalize_decision(raw_decision)

valid_decisions = {
    "APPROVE_ALL_PROPOSED_ACTIONS",
    "APPROVE_LIMITED",
    "REJECT",
    "FALSE_POSITIVE",
    "ESCALATE",
    "ACKNOWLEDGE_AND_MONITOR",
    "CLOSE_NO_ACTION",
}

if decision not in valid_decisions:
    errors.append("VALID_ANALYST_DECISION_MISSING")

analyst_identity = str(
    find_nonempty_field(
        payload,
        [
            "analyst_identity",
            "analyst_user",
            "analyst_email",
            "user",
        ],
    )
    or ""
).strip()

if not analyst_identity:
    errors.append("ANALYST_IDENTITY_MISSING")

approved_actions = ensure_action_list(
    find_nonempty_field(
        payload,
        [
            "returned_approved_actions",
            "selected_actions",
            "approved_actions",
        ],
    )
)

if decision == "APPROVE_LIMITED" and not approved_actions:
    errors.append(
        "LIMITED_APPROVAL_HAS_NO_SELECTED_ACTIONS"
    )

if decision not in (
    "APPROVE_ALL_PROPOSED_ACTIONS",
    "APPROVE_LIMITED",
):
    approved_actions = []

decision_time = find_nonempty_field(
    payload,
    [
        "decision_time",
        "analyst_decision_time",
        "clicked_at",
        "timestamp",
    ],
)

if not decision_time:
    decision_time = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

decision_note = find_nonempty_field(
    payload,
    [
        "decision_note",
        "analyst_note",
        "analyst_comment",
        "note",
        "comment",
    ],
)

decision_id = str(
    find_nonempty_field(payload, ["decision_id"])
    or ""
).strip()

decision_source = str(
    find_nonempty_field(payload, ["decision_source"])
    or "UNSPECIFIED"
).strip()

receiver_valid = len(errors) == 0

output = {
    "receiver_valid": receiver_valid,
    "receiver_status": (
        "PB04_ANALYST_DECISION_RECEIVED"
        if receiver_valid
        else "FAILED_CLOSED"
    ),
    "receiver_errors": errors,
    "schema_version": str(
        payload.get("schema_version", "PB04_DECISION_V1")
    ),
    "playbook_id": str(
        payload.get("playbook_id", "PB04")
    ),
    "decision_id": decision_id,
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,
    "case_status": optional_case_record.get(
        "case_status",
        "",
    ),
    "analyst_decision": decision,
    "analyst_identity": analyst_identity,
    "analyst_decision_time": str(decision_time),
    "analyst_note": str(decision_note or ""),
    "decision_source": decision_source,
    "approved_actions_requested": approved_actions,
    "case_executable_actions": [],
    "case_record": optional_case_record,
    "approval_valid": False,
    "identity_action_authorized": False,
    "automated_response_allowed": False,
    "received_at": (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    ),
}

print(json.dumps(output))
