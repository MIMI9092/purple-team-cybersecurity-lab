import json
import re
from datetime import datetime, timezone


def normalize_key(value):
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        str(value).lower(),
    ).strip("_")


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
                found = find_row(
                    value[key],
                    marker_fields,
                )

                if found is not None:
                    return found

        for child in value.values():
            found = find_row(
                child,
                marker_fields,
            )

            if found is not None:
                return found

    elif isinstance(value, list):
        for child in value:
            found = find_row(
                child,
                marker_fields,
            )

            if found is not None:
                return found

    return None


def get_ci(mapping, name, default=None):
    if not isinstance(mapping, dict):
        return default

    wanted = normalize_key(name)

    for key, value in mapping.items():
        if normalize_key(key) == wanted:
            return value

    return default


def has_ci(mapping, name):
    if not isinstance(mapping, dict):
        return False

    wanted = normalize_key(name)

    return any(
        normalize_key(key) == wanted
        for key in mapping.keys()
    )


def to_bool(value):
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in (
        "true",
        "1",
        "yes",
        "enabled",
        "success",
    )


def to_int(value, default=0):
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def ensure_list(value):
    if value is None or value == "":
        return []

    if isinstance(value, list):
        return value

    return [value]


def merge_unique(first, second):
    merged = []
    seen = set()

    for item in ensure_list(first) + ensure_list(second):
        try:
            marker = json.dumps(
                item,
                sort_keys=True,
                default=str,
            )
        except Exception:
            marker = str(item)

        if marker in seen:
            continue

        seen.add(marker)
        merged.append(item)

    return merged


profile_output = decode_json(
    r'''$select_pb04_identity_response_profile'''
)

context = find_row(
    profile_output,
    [
        "profile_selection_valid",
        "response_profile",
        "proposed_actions",
    ],
) or {}


existing_output = decode_json(
    r'''$check_for_existing_pb04_case'''
)

existing_lookup = find_row(
    existing_output,
    [
        "found",
        "value",
        "key",
        "category",
    ],
) or {}


existing_lookup_valid = (
    isinstance(existing_lookup, dict)
    and has_ci(existing_lookup, "success")
)

existing_lookup_success = (
    to_bool(get_ci(existing_lookup, "success"))
    if existing_lookup_valid
    else False
)

existing_found_field_present = has_ci(
    existing_lookup,
    "found",
)

existing_value_field_present = has_ci(
    existing_lookup,
    "value",
)

if existing_found_field_present:
    existing_found = to_bool(
        get_ci(existing_lookup, "found", False)
    )
else:
    existing_found = existing_value_field_present


existing_value = decode_json(
    get_ci(existing_lookup, "value", {})
)

if (
    isinstance(existing_value, dict)
    and isinstance(
        existing_value.get("case_record"),
        dict,
    )
):
    existing_case = existing_value["case_record"]

elif isinstance(existing_value, dict):
    existing_case = existing_value

else:
    existing_case = {}


existing_case_found = (
    existing_lookup_valid
    and existing_lookup_success
    and existing_found
    and bool(existing_case)
)


errors = []

if not to_bool(
    context.get("profile_selection_valid")
):
    errors.append(
        "RESPONSE_PROFILE_SELECTION_MISSING_OR_INVALID"
    )

if not existing_lookup_valid:
    errors.append(
        "EXISTING_CASE_LOOKUP_UNAVAILABLE"
    )

elif not existing_lookup_success:
    errors.append(
        "EXISTING_CASE_LOOKUP_FAILED"
    )

elif existing_found and not existing_case:
    errors.append(
        "EXISTING_CASE_VALUE_INVALID"
    )


case_id = str(
    context.get("case_id", "")
).strip()

campaign_id = str(
    context.get("campaign_id", "")
).strip()

detection_id = str(
    context.get("detection_id", "")
).upper()

response_profile = str(
    context.get("response_profile", "")
).upper()


if existing_case_found:
    existing_campaign_id = str(
        existing_case.get(
            "campaign_id",
            existing_case.get(
                "case_lookup_key",
                "",
            ),
        )
    ).strip()

    if (
        existing_campaign_id
        and campaign_id
        and existing_campaign_id != campaign_id
    ):
        errors.append(
            "EXISTING_CASE_CAMPAIGN_ID_MISMATCH"
        )

    existing_case_id = str(
        existing_case.get("case_id", "")
    ).strip()

    if existing_case_id:
        case_id = existing_case_id


if not case_id:
    errors.append("CASE_ID_MISSING")

if not campaign_id:
    errors.append("CAMPAIGN_ID_MISSING")

if detection_id not in ("D14", "D15"):
    errors.append("INVALID_DETECTION_ID")

if response_profile not in (
    "IRP0",
    "IRP1",
    "IRP2",
    "IRP3",
    "IRP4",
):
    errors.append("INVALID_RESPONSE_PROFILE")


if errors:
    print(json.dumps({
        "case_build_valid": False,
        "case_build_status": "FAILED_CLOSED",
        "case_build_errors": errors,
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_record": {},
        "existing_case_found": existing_case_found,
        "notification_required": False,
        "analyst_decision_required": False,
        "automated_response_allowed": False,
    }))

    raise SystemExit


now_utc = datetime.now(timezone.utc)
now_iso = now_utc.isoformat().replace(
    "+00:00",
    "Z",
)


if existing_case_found:
    created_at = str(
        existing_case.get("created_at", now_iso)
    )

    case_version = (
        to_int(
            existing_case.get("case_version"),
            1,
        )
        + 1
    )

    deduplication_status = (
        "EXISTING_CASE_UPDATED"
    )

else:
    created_at = now_iso
    case_version = 1
    deduplication_status = "NEW_CASE"


proposed_actions = ensure_list(
    context.get("proposed_actions")
)

approval_required_actions = ensure_list(
    context.get("approval_required_actions")
)

executable_actions = ensure_list(
    context.get(
        "executable_actions_after_approval"
    )
)

deferred_actions = ensure_list(
    context.get("deferred_actions")
)

refused_actions = ensure_list(
    context.get("refused_actions")
)

investigation_actions = ensure_list(
    context.get("investigation_actions")
)

new_evidence_timeline = ensure_list(
    context.get("evidence_timeline")
)


existing_evidence = existing_case.get(
    "evidence",
    {},
)

if not isinstance(existing_evidence, dict):
    existing_evidence = {}


evidence_timeline = merge_unique(
    existing_evidence.get("timeline", []),
    new_evidence_timeline,
)


analyst_decision_required = to_bool(
    context.get("analyst_decision_required")
)


if response_profile == "IRP0":
    case_status = "CLOSED_AUTHORIZED_TEST"
    next_step = (
        "PERSIST_AUTHORIZED_CLOSURE_AUDIT"
    )
    allowed_decisions = []

elif executable_actions:
    case_status = (
        "AWAITING_ANALYST_APPROVAL"
    )
    next_step = "LAUNCH_ANALYST_APPROVAL"

    allowed_decisions = [
        "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVE_LIMITED",
        "REJECT",
        "FALSE_POSITIVE",
        "ESCALATE",
    ]

else:
    case_status = "AWAITING_ANALYST_REVIEW"
    next_step = "LAUNCH_ANALYST_REVIEW"

    allowed_decisions = [
        "ACKNOWLEDGE_AND_MONITOR",
        "CLOSE_NO_ACTION",
        "FALSE_POSITIVE",
        "ESCALATE",
    ]


notification_required = (
    response_profile != "IRP0"
    and not existing_case_found
)


requester_account = str(
    context.get("requester_account", "")
)

target_account = str(
    context.get("target_account", "")
)

client_address = str(
    context.get("client_address", "")
)

identity_stage = str(
    context.get("identity_stage", "")
).upper()

identity_outcome = str(
    context.get("identity_outcome", "")
)

risk_level = str(
    context.get(
        "risk_level",
        "UNDETERMINED",
    )
).upper()

risk_score = context.get("risk_score")

priority = str(
    context.get(
        "priority",
        "UNDETERMINED",
    )
).upper()


analyst_title = (
    "["
    + priority
    + "] PB04 "
    + identity_stage
    + " - "
    + target_account
)


summary_lines = [
    "PB04 IDENTITY CASE",
    "",
    "Case ID: " + case_id,
    "Campaign ID: " + campaign_id,
    "Detection: " + detection_id,
    "",
    "Requester: " + requester_account,
    "Target account: " + target_account,
    "Client address: " + client_address,
    "",
    (
        "Identity assessment: "
        + identity_stage
        + " - "
        + identity_outcome
    ),
    (
        "Evidence correlation: "
        + str(
            context.get(
                "evidence_correlation_strength",
                "NONE",
            )
        )
    ),
    (
        "Risk: "
        + risk_level
        + " ("
        + str(risk_score)
        + "/100)"
    ),
    (
        "Response profile: "
        + response_profile
        + " - "
        + str(
            context.get(
                "response_profile_name",
                "",
            )
        )
    ),
    "",
    (
        "Temporary disable eligible: "
        + str(
            to_bool(
                context.get(
                    "temporary_disable_eligible"
                )
            )
        ).lower()
    ),
    (
        "Credential rotation: "
        + str(
            context.get(
                "credential_rotation_status",
                "ROTATION_NOT_SELECTED",
            )
        )
    ),
    (
        "Deduplication: "
        + deduplication_status
    ),
    "",
    (
        "No identity-changing action may execute "
        "without a valid analyst decision and a "
        "fresh safety check."
    ),
]

analyst_summary = "\n".join(summary_lines)


new_analyst_decision = {
    "required": analyst_decision_required,
    "status": (
        "NOT_REQUIRED"
        if response_profile == "IRP0"
        else "PENDING"
    ),
    "allowed_decisions": allowed_decisions,
    "approved_actions": [],
    "analyst_identity": "",
    "decision_time": "",
}


existing_analyst_decision = existing_case.get(
    "analyst_decision",
    {},
)

if (
    existing_case_found
    and isinstance(
        existing_analyst_decision,
        dict,
    )
):
    existing_status = str(
        existing_analyst_decision.get(
            "status",
            "",
        )
    ).strip()

    if existing_status:
        new_analyst_decision["status"] = (
            existing_status
        )

    new_analyst_decision[
        "approved_actions"
    ] = ensure_list(
        existing_analyst_decision.get(
            "approved_actions",
            [],
        )
    )

    new_analyst_decision[
        "analyst_identity"
    ] = str(
        existing_analyst_decision.get(
            "analyst_identity",
            "",
        )
    )

    new_analyst_decision[
        "decision_time"
    ] = str(
        existing_analyst_decision.get(
            "decision_time",
            "",
        )
    )


case_record = {
    "schema_version": "PB04_CASE_V1",
    "playbook_id": context.get(
        "playbook_id",
        "PB04",
    ),
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,
    "case_version": case_version,
    "case_status": case_status,
    "created_at": created_at,
    "updated_at": now_iso,

    "detection": {
        "detection_id": detection_id,
        "initial_identity_stage": context.get(
            "initial_identity_stage",
            "",
        ),
        "detection_reason": context.get(
            "detection_reason",
            "",
        ),
    },

    "entities": {
        "requester_account": requester_account,
        "target_account": target_account,
        "target_accounts": ensure_list(
            context.get("target_accounts")
        ),
        "client_address": client_address,
    },

    "authorization": {
        "authorization_status": context.get(
            "authorization_status",
            "",
        ),
        "authorized_test": to_bool(
            context.get("authorized_test")
        ),
        "scope_reason": context.get(
            "authorization_scope_reason",
            "",
        ),
    },

    "identity_asset": {
        "identity_known": to_bool(
            context.get("identity_known")
        ),
        "account_type": context.get(
            "account_type",
            "UNKNOWN",
        ),
        "business_criticality": context.get(
            "business_criticality",
            "UNKNOWN",
        ),
        "privileged_account": to_bool(
            context.get("privileged_account")
        ),
        "break_glass_account": to_bool(
            context.get("break_glass_account")
        ),
        "temporary_disable_allowed": to_bool(
            context.get(
                "temporary_disable_allowed"
            )
        ),
        "dependency_review_required": to_bool(
            context.get(
                "dependency_review_required"
            )
        ),
        "identity_safety_status": context.get(
            "identity_safety_status",
            "",
        ),
    },

    "assessment": {
        "identity_stage": identity_stage,
        "identity_outcome": identity_outcome,
        "outcome_reason": context.get(
            "outcome_reason",
            "",
        ),
        "account_use_established": to_bool(
            context.get(
                "account_use_established"
            )
        ),
        "account_use_signals": ensure_list(
            context.get("account_use_signals")
        ),
        "strong_post_compromise_signals": (
            ensure_list(
                context.get(
                    "strong_post_compromise_signals"
                )
            )
        ),
        "elevated_exposure_signals": ensure_list(
            context.get(
                "elevated_exposure_signals"
            )
        ),
        "evidence_correlation_strength": (
            context.get(
                "evidence_correlation_strength",
                "NONE",
            )
        ),
    },

    "risk": {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "priority": priority,
        "risk_factors": ensure_list(
            context.get("risk_factors")
        ),
        "risk_model_version": context.get(
            "risk_model_version",
            "",
        ),
    },

    "response": {
        "response_profile": response_profile,
        "response_profile_name": context.get(
            "response_profile_name",
            "",
        ),
        "selection_reason": context.get(
            "profile_selection_reason",
            "",
        ),
        "proposed_actions": proposed_actions,
        "approval_required_actions": (
            approval_required_actions
        ),
        "executable_actions_after_approval": (
            executable_actions
        ),
        "deferred_actions": deferred_actions,
        "refused_actions": refused_actions,
        "investigation_actions": (
            investigation_actions
        ),
        "rotation_recommended": to_bool(
            context.get("rotation_recommended")
        ),
        "secondary_containment_consideration": (
            to_bool(
                context.get(
                    "secondary_containment_consideration"
                )
            )
        ),
    },

    "evidence": {
        "retrieval_status": context.get(
            "evidence_retrieval_status",
            "",
        ),
        "total_matching_events": context.get(
            "total_matching_events",
            0,
        ),
        "post_access_host_count": context.get(
            "post_access_host_count",
            0,
        ),
        "timeline": evidence_timeline,
    },

    "analyst_decision": new_analyst_decision,

    "verification": {
        "required": bool(executable_actions),
        "status": "NOT_STARTED",
    },

    "audit": {
        "deduplication_status": (
            deduplication_status
        ),
        "existing_case_found": (
            existing_case_found
        ),
        "notification_required": (
            notification_required
        ),
        "open_case_datastore_category": (
            "pb04_identity_cases"
        ),
        "final_audit_datastore_category": (
            "pb04_identity_case_audit"
        ),
        "next_step": next_step,
    },
}


print(json.dumps({
    "schema_version": "1.0",
    "playbook_id": context.get(
        "playbook_id",
        "PB04",
    ),
    "notification_type": (
        "PB04_ANALYST_REVIEW_REQUIRED"
    ),
    "subject": analyst_title,
    "html_body": (
        "<pre style=\"font-family:Arial,sans-serif;"
        "white-space:pre-wrap;\">"
        + analyst_summary
        + "</pre>"
    ),
    "case_build_valid": True,
    "case_build_status": (
        "PB04_EXISTING_CASE_UPDATED"
        if existing_case_found
        else "PB04_ANALYST_CASE_BUILT"
    ),
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,
    "case_version": case_version,
    "case_status": case_status,
    "response_profile": response_profile,
    "risk_level": risk_level,
    "priority": priority,
    "existing_case_found": existing_case_found,
    "deduplication_status": (
        deduplication_status
    ),
    "notification_required": (
        notification_required
    ),
    "analyst_decision_required": (
        analyst_decision_required
    ),
    "approval_required_actions": (
        approval_required_actions
    ),
    "executable_actions_after_approval": (
        executable_actions
    ),
    "allowed_decisions": allowed_decisions,
    "next_step": next_step,
    "analyst_title": analyst_title,
    "analyst_summary": analyst_summary,
    "case_record": case_record,
    "automated_response_allowed": False,
}))
