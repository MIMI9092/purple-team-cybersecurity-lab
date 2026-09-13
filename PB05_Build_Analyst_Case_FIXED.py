import html
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


def find_profile(value):
    value = decode_json(value)

    if isinstance(value, dict):
        keys = {
            normalize_key(key)
            for key in value.keys()
        }

        if (
            "profile_selection_valid" in keys
            and "response_profile" in keys
        ):
            return value

        for preferred_key in (
            "message",
            "result",
            "body",
            "data",
            "content",
            "output",
        ):
            for key, child in value.items():
                if (
                    normalize_key(key)
                    == preferred_key
                ):
                    found = find_profile(child)

                    if found is not None:
                        return found

        for child in value.values():
            found = find_profile(child)

            if found is not None:
                return found

    elif isinstance(value, list):
        for child in value:
            found = find_profile(child)

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
        "passed",
        "valid",
        "found",
    )


def to_int(value, default=0):
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def ensure_list(value):
    value = decode_json(value)

    if value in (None, "", [], {}):
        return []

    if isinstance(value, list):
        return value

    return [value]


def merge_unique(first, second):
    merged = []
    seen = set()

    for item in (
        ensure_list(first)
        + ensure_list(second)
    ):
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


def text(value):
    if value is None:
        return ""

    return str(value).strip()


raw_input = decode_json(
    r'''$select_pb05_containment_response_profile'''
)

receiver_wrapper = decode_json(
    r'''$receive_pb05_investigation_context'''
)

if isinstance(receiver_wrapper, dict):
    receiver_context = decode_json(
        receiver_wrapper.get(
            "message",
            receiver_wrapper,
        )
    )
else:
    receiver_context = {}

if not isinstance(receiver_context, dict):
    receiver_context = {}

context = find_profile(
    raw_input
)

errors = []

if not isinstance(context, dict):
    context = {}
    errors.append(
        "PB05_RESPONSE_PROFILE_CONTEXT_NOT_FOUND"
    )

if not to_bool(
    context.get(
        "profile_selection_valid"
    )
):
    errors.append(
        "PB05_RESPONSE_PROFILE_INVALID"
    )


case_id = text(
    context.get("case_id")
)

campaign_id = text(
    context.get("campaign_id")
)

detection_id = text(
    context.get("detection_id")
).upper()

final_stage = text(
    context.get(
        "final_attack_stage",
        "UNDETERMINED",
    )
).upper()

response_profile = text(
    context.get(
        "response_profile"
    )
).upper()

risk_level = text(
    context.get(
        "risk_level",
        "UNDETERMINED",
    )
).upper()

risk_score = context.get(
    "risk_score"
)

priority = text(
    context.get(
        "priority",
        "UNDETERMINED",
    )
).upper()


if not case_id.startswith(
    "PB05-CASE-"
):
    errors.append(
        "CASE_ID_MISSING_OR_INVALID"
    )

if not campaign_id.startswith(
    "PB05-CMP-"
):
    errors.append(
        "CAMPAIGN_ID_MISSING_OR_INVALID"
    )

if response_profile not in (
    "CRP0",
    "CRP1",
    "CRP2",
    "CRP3",
    "CRP4",
):
    errors.append(
        "INVALID_RESPONSE_PROFILE"
    )


existing_case_found = to_bool(
    context.get(
        "existing_case_found"
    )
)

existing_case = decode_json(
    context.get(
        "existing_case_record",
        {},
    )
)

if not isinstance(
    existing_case,
    dict,
):
    existing_case = {}

if existing_case_found:
    existing_case_id = text(
        existing_case.get(
            "case_id"
        )
    )

    existing_campaign_id = text(
        existing_case.get(
            "campaign_id",
            existing_case.get(
                "case_lookup_key",
                "",
            ),
        )
    )

    if existing_case_id:
        case_id = existing_case_id

    if (
        existing_campaign_id
        and existing_campaign_id
        != campaign_id
    ):
        errors.append(
            "EXISTING_CASE_CAMPAIGN_MISMATCH"
        )


now_iso = (
    datetime.now(timezone.utc)
    .isoformat()
    .replace("+00:00", "Z")
)

if existing_case_found:
    created_at = text(
        existing_case.get(
            "created_at",
            now_iso,
        )
    )

    case_version = (
        to_int(
            existing_case.get(
                "case_version"
            ),
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


profile_execution_eligible = to_bool(
    context.get(
        "profile_execution_eligible"
    )
)

assessment_incomplete = to_bool(
    context.get(
        "assessment_incomplete"
    )
)

approval_required_actions = ensure_list(
    context.get(
        "approval_required_actions"
    )
)

executable_actions = ensure_list(
    context.get(
        "executable_actions_after_approval"
    )
)

proposed_actions = ensure_list(
    context.get(
        "proposed_actions"
    )
)

required_verification_controls = ensure_list(
    context.get(
        "required_verification_controls"
    )
)


if response_profile == "CRP0":
    case_status = (
        "CLOSED_AUTHORIZED_TEST"
    )
    next_step = (
        "PERSIST_AUTHORIZED_CLOSURE_AUDIT"
    )
    allowed_decisions = []

elif (
    response_profile in (
        "CRP2",
        "CRP3",
        "CRP4",
    )
    and profile_execution_eligible
):
    case_status = (
        "AWAITING_ANALYST_APPROVAL"
    )
    next_step = (
        "LAUNCH_ANALYST_APPROVAL"
    )
    allowed_decisions = [
        "APPROVE_ALL_PROPOSED_ACTIONS",
        "APPROVE_LIMITED",
        "REJECT",
        "FALSE_POSITIVE",
        "ESCALATE",
    ]

elif (
    assessment_incomplete
    or (
        response_profile in (
            "CRP2",
            "CRP3",
            "CRP4",
        )
        and not profile_execution_eligible
    )
):
    case_status = (
        "AWAITING_ANALYST_ESCALATION"
    )
    next_step = (
        "LAUNCH_ANALYST_ESCALATION"
    )
    allowed_decisions = [
        "ESCALATE",
        "REJECT",
        "FALSE_POSITIVE",
        "ACKNOWLEDGE_AND_MONITOR",
    ]

else:
    case_status = (
        "AWAITING_ANALYST_REVIEW"
    )
    next_step = (
        "LAUNCH_ANALYST_REVIEW"
    )
    allowed_decisions = [
        "ACKNOWLEDGE_AND_MONITOR",
        "CLOSE_NO_ACTION",
        "FALSE_POSITIVE",
        "ESCALATE",
    ]


stage_ranks = {
    "UNDETERMINED": 0,
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
}

profile_ranks = {
    "CRP0": 0,
    "CRP1": 1,
    "CRP2": 2,
    "CRP3": 3,
    "CRP4": 4,
}

priority_ranks = {
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
    "UNDETERMINED": 99,
}


existing_assessment = existing_case.get(
    "assessment",
    {},
)

if not isinstance(
    existing_assessment,
    dict,
):
    existing_assessment = {}

existing_response = existing_case.get(
    "response",
    {},
)

if not isinstance(
    existing_response,
    dict,
):
    existing_response = {}

existing_risk = existing_case.get(
    "risk",
    {},
)

if not isinstance(
    existing_risk,
    dict,
):
    existing_risk = {}


existing_stage = text(
    existing_assessment.get(
        "final_attack_stage",
        "UNDETERMINED",
    )
).upper()

existing_profile = text(
    existing_response.get(
        "response_profile",
        "CRP0",
    )
).upper()

existing_priority = text(
    existing_risk.get(
        "priority",
        "UNDETERMINED",
    )
).upper()


material_escalation = (
    stage_ranks.get(
        final_stage,
        0,
    )
    > stage_ranks.get(
        existing_stage,
        0,
    )
    or profile_ranks.get(
        response_profile,
        0,
    )
    > profile_ranks.get(
        existing_profile,
        0,
    )
    or priority_ranks.get(
        priority,
        99,
    )
    < priority_ranks.get(
        existing_priority,
        99,
    )
)


notification_required = (
    response_profile != "CRP0"
    and (
        not existing_case_found
        or material_escalation
    )
)

analyst_decision_required = (
    response_profile != "CRP0"
)


new_detection_reference = {
    "detection_id": detection_id,
    "search_name": context.get(
        "search_name",
        "",
    ),
    "detection_key": context.get(
        "detection_key",
        "",
    ),
    "observed_at": context.get(
        "first_seen",
        context.get(
            "event_time",
            "",
        ),
    ),
    "initial_attack_stage": (
        context.get(
            "initial_attack_stage",
            "",
        )
    ),
}

existing_detections = existing_case.get(
    "detections",
    [],
)

detections = merge_unique(
    existing_detections,
    [new_detection_reference],
)


existing_evidence = existing_case.get(
    "evidence",
    {},
)

if not isinstance(
    existing_evidence,
    dict,
):
    existing_evidence = {}

evidence_timeline = merge_unique(
    existing_evidence.get(
        "timeline",
        [],
    ),
    context.get(
        "evidence_timeline",
        [],
    ),
)

correlation_indicators = merge_unique(
    existing_evidence.get(
        "correlation_indicators",
        [],
    ),
    context.get(
        "correlation_indicators",
        [],
    ),
)

telemetry_gaps = merge_unique(
    existing_evidence.get(
        "telemetry_gaps",
        [],
    ),
    context.get(
        "telemetry_gaps",
        [],
    ),
)


endpoint_host = text(
    context.get(
        "endpoint_host"
    )
).upper()

affected_user = text(
    context.get(
        "affected_user"
    )
).lower()

network_evidence = context.get(
    "network_evidence",
    {},
)

if not isinstance(
    network_evidence,
    dict,
):
    network_evidence = {}

callback_address = text(
    network_evidence.get("runtime_callback")
    or context.get(
        "callback_address",
        "",
    )
)

callback_port = text(
    network_evidence.get("runtime_callback_port")
    or context.get(
        "callback_port",
        "",
    )
)


existing_action_targets = decode_json(
    existing_evidence.get(
        "action_targets",
        {},
    )
)

if not isinstance(
    existing_action_targets,
    dict,
):
    existing_action_targets = {}


receiver_action_targets = {
    "source_detection_id": detection_id,
    "process_id": text(
        receiver_context.get(
            "process_id"
        )
    ),
    "process_creation_time": text(
        receiver_context.get(
            "process_creation_time"
        )
    ),
    "process_path": text(
        receiver_context.get(
            "process_path"
        )
    ),
    "process_command_line": text(
        receiver_context.get(
            "process_command_line",
            receiver_context.get(
                "command_line",
                "",
            ),
        )
    ),
    "process_user": text(
        receiver_context.get(
            "process_user",
            receiver_context.get(
                "affected_user",
                affected_user,
            ),
        )
    ),
    "run_key_path": text(
        receiver_context.get(
            "run_key_path"
        )
    ),
    "run_value_name": text(
        receiver_context.get(
            "run_value_name"
        )
    ),
    "run_value_data": text(
        receiver_context.get(
            "run_value_data"
        )
    ),
    "persistence_script_path": text(
        receiver_context.get(
            "persistence_script_path",
            receiver_context.get(
                "script_path",
                "",
            ),
        )
    ),
    "callback_address": text(
        receiver_context.get(
            "callback_address",
            callback_address,
        )
    ),
    "callback_port": text(
        receiver_context.get(
            "callback_port",
            callback_port,
        )
    ),
    "captured_at": text(
        receiver_context.get(
            "normalized_at",
            now_iso,
        )
    ),
    "source": "PB05_RECEIVED_ALERT_CONTEXT",
}


action_targets = {}

for field_name in (
    "source_detection_id",
    "process_id",
    "process_creation_time",
    "process_path",
    "process_command_line",
    "process_user",
    "run_key_path",
    "run_value_name",
    "run_value_data",
    "persistence_script_path",
    "callback_address",
    "callback_port",
    "captured_at",
    "source",
):
    field_value = receiver_action_targets.get(
        field_name
    )

    if field_value in (
        None,
        "",
        [],
        {},
    ):
        field_value = existing_action_targets.get(
            field_name
        )

    if field_value not in (
        None,
        "",
        [],
        {},
    ):
        action_targets[field_name] = field_value


analyst_title = (
    "["
    + priority
    + "] PB05 "
    + final_stage
    + " - "
    + endpoint_host
    + " / "
    + affected_user
)

summary_lines = [
    "PB05 ENDPOINT PERSISTENCE AND C2 CASE",
    "",
    "Case ID: " + case_id,
    "Campaign ID: " + campaign_id,
    "Detection: " + detection_id,
    "",
    "Endpoint: " + endpoint_host,
    (
        "Endpoint address: "
        + text(
            context.get(
                "endpoint_address"
            )
        )
    ),
    "Affected user: " + affected_user,
    (
        "Callback: "
        + callback_address
        + (
            ":" + callback_port
            if callback_port
            else ""
        )
    ),
    "",
    (
        "Initial hypothesis: "
        + text(
            context.get(
                "initial_attack_stage"
            )
        )
    ),
    (
        "Final assessment: "
        + final_stage
        + " - "
        + text(
            context.get(
                "attack_stage_name"
            )
        )
    ),
    (
        "Evidence correlation: "
        + text(
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
        + text(risk_score)
        + "/100)"
    ),
    (
        "Response profile: "
        + response_profile
        + " - "
        + text(
            context.get(
                "response_profile_name"
            )
        )
    ),
    "",
    (
        "Proposed actions: "
        + (
            ", ".join(
                str(item)
                for item in proposed_actions
            )
            if proposed_actions
            else "None"
        )
    ),
    (
        "Executable after approval: "
        + (
            ", ".join(
                str(item)
                for item in executable_actions
            )
            if executable_actions
            else "None"
        )
    ),
    (
        "Deferred actions: "
        + ", ".join(
            str(item)
            for item in ensure_list(
                context.get(
                    "deferred_actions"
                )
            )
        )
    ),
    (
        "Policy failures: "
        + (
            ", ".join(
                str(item)
                for item in ensure_list(
                    context.get(
                        "policy_failures"
                    )
                )
            )
            or "None"
        )
    ),
    "",
    (
        "No endpoint or firewall write may execute "
        "without a valid analyst decision, a "
        "persisted evidence snapshot and fresh "
        "live-state safety validation."
    ),
]

analyst_summary = "\n".join(
    summary_lines
)


existing_decision = existing_case.get(
    "analyst_decision",
    {},
)

if not isinstance(
    existing_decision,
    dict,
):
    existing_decision = {}

if (
    existing_case_found
    and not material_escalation
    and text(
        existing_decision.get(
            "status"
        )
    )
):
    decision_status = text(
        existing_decision.get(
            "status"
        )
    )
else:
    decision_status = (
        "NOT_REQUIRED"
        if response_profile == "CRP0"
        else "PENDING"
    )

analyst_decision = {
    "required": analyst_decision_required,
    "status": decision_status,
    "allowed_decisions": allowed_decisions,
    "approved_actions": (
        []
        if material_escalation
        else ensure_list(
            existing_decision.get(
                "approved_actions"
            )
        )
    ),
    "analyst_identity": (
        ""
        if material_escalation
        else text(
            existing_decision.get(
                "analyst_identity"
            )
        )
    ),
    "decision_time": (
        ""
        if material_escalation
        else text(
            existing_decision.get(
                "decision_time"
            )
        )
    ),
}


case_record = {
    "schema_version": "PB05_CASE_V1",
    "playbook_id": "PB05",

    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,
    "case_version": case_version,
    "case_status": case_status,
    "created_at": created_at,
    "updated_at": now_iso,

    "detections": detections,

    "entities": {
        "endpoint_host": endpoint_host,
        "endpoint_address": context.get(
            "endpoint_address",
            "",
        ),
        "affected_user": affected_user,
        "affected_domain": context.get(
            "affected_domain",
            "",
        ),
        "user_sid": context.get(
            "user_sid",
            "",
        ),
        "callback_address": (
            callback_address
        ),
        "callback_port": callback_port,
    },

    "authorization": {
        "authorization_status": (
            context.get(
                "authorization_status",
                "NOT_AUTHORIZED",
            )
        ),
        "authorized_test": to_bool(
            context.get(
                "authorized_test"
            )
        ),
        "scope_reason": context.get(
            "authorization_scope_reason",
            "",
        ),
    },

    "endpoint_asset": context.get(
        "endpoint_asset",
        {},
    ),

    "assessment": {
        "initial_attack_stage": (
            context.get(
                "initial_attack_stage",
                "",
            )
        ),
        "evidence_derived_stage": (
            context.get(
                "evidence_derived_stage",
                "",
            )
        ),
        "final_attack_stage": (
            final_stage
        ),
        "attack_stage_name": (
            context.get(
                "attack_stage_name",
                "",
            )
        ),
        "stage_reason": context.get(
            "stage_reason",
            "",
        ),
        "assessment_incomplete": (
            assessment_incomplete
        ),
        "stage_confidence": context.get(
            "stage_confidence",
            "",
        ),
    },

    "risk": {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "priority": priority,
        "risk_scope": context.get(
            "risk_scope",
            "",
        ),
        "risk_factors": ensure_list(
            context.get(
                "risk_factors"
            )
        ),
        "risk_model_version": (
            context.get(
                "risk_model_version",
                "",
            )
        ),
    },

    "response": {
        "response_profile": (
            response_profile
        ),
        "response_profile_name": (
            context.get(
                "response_profile_name",
                "",
            )
        ),
        "selection_reason": (
            context.get(
                "profile_selection_reason",
                "",
            )
        ),
        "proposed_actions": (
            proposed_actions
        ),
        "approval_required_actions": (
            approval_required_actions
        ),
        "executable_actions_after_approval": (
            executable_actions
        ),
        "required_verification_controls": (
            required_verification_controls
        ),
        "containment_order": ensure_list(
            context.get(
                "containment_order"
            )
        ),
        "deferred_actions": ensure_list(
            context.get(
                "deferred_actions"
            )
        ),
        "refused_actions": ensure_list(
            context.get(
                "refused_actions"
            )
        ),
        "manual_actions_recommended": (
            ensure_list(
                context.get(
                    "manual_actions_recommended"
                )
            )
        ),
        "policy_failures": ensure_list(
            context.get(
                "policy_failures"
            )
        ),
        "profile_execution_eligible": (
            profile_execution_eligible
        ),
        "host_isolation_status": (
            context.get(
                "host_isolation_status",
                "",
            )
        ),
        "binary_deletion_status": (
            context.get(
                "binary_deletion_status",
                "",
            )
        ),
    },

    "evidence": {
        "correlation_strength": (
            context.get(
                "evidence_correlation_strength",
                "NONE",
            )
        ),
        "completeness": context.get(
            "evidence_completeness",
            "",
        ),
        "correlation_indicators": (
            correlation_indicators
        ),
        "telemetry_gaps": telemetry_gaps,
        "timeline": evidence_timeline,
        "persistence": context.get(
            "persistence_evidence",
            {},
        ),
        "process": context.get(
            "process_evidence",
            {},
        ),
        "network": network_evidence,
        "action_targets": action_targets,
    },

    "analyst_decision": (
        analyst_decision
    ),

    "verification": {
        "required": bool(
            executable_actions
        ),
        "required_controls": (
            required_verification_controls
        ),
        "status": "NOT_STARTED",
    },

    "audit": {
        "deduplication_status": (
            deduplication_status
        ),
        "existing_case_found": (
            existing_case_found
        ),
        "material_escalation": (
            material_escalation
        ),
        "notification_required": (
            notification_required
        ),
        "open_case_datastore_category": (
            "pb05_persistence_c2_cases"
        ),
        "evidence_snapshot_category": (
            "pb05_evidence_snapshots"
        ),
        "final_audit_category": (
            "pb05_persistence_c2_audit"
        ),
        "next_step": next_step,
    },
}


case_build_valid = (
    len(errors) == 0
)

if profile_execution_eligible:
    notification_type = (
        "PB05_ANALYST_APPROVAL_REQUIRED"
    )
else:
    notification_type = (
        "PB05_ANALYST_REVIEW_REQUIRED"
    )

if response_profile == "CRP0":
    notification_type = (
        "PB05_AUTHORIZED_CLOSURE"
    )


output = {
    "schema_version": "1.0",
    "playbook_id": "PB05",
    "notification_type": (
        notification_type
    ),
    "subject": analyst_title,
    "html_body": (
        "<pre style=\"font-family:Arial,sans-serif;"
        "white-space:pre-wrap;\">"
        + html.escape(analyst_summary)
        + "</pre>"
    ),

    "case_build_valid": (
        case_build_valid
    ),
    "case_build_status": (
        "FAILED_CLOSED"
        if not case_build_valid
        else (
            "PB05_EXISTING_CASE_UPDATED"
            if existing_case_found
            else "PB05_ANALYST_CASE_BUILT"
        )
    ),
    "case_build_errors": errors,

    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,
    "case_version": case_version,
    "case_status": case_status,

    "detection_id": detection_id,
    "final_attack_stage": final_stage,
    "response_profile": response_profile,
    "risk_level": risk_level,
    "risk_score": risk_score,
    "priority": priority,

    "existing_case_found": (
        existing_case_found
    ),
    "deduplication_status": (
        deduplication_status
    ),
    "material_escalation": (
        material_escalation
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
    "allowed_decisions": (
        allowed_decisions
    ),
    "next_step": next_step,

    "analyst_title": analyst_title,
    "analyst_summary": (
        analyst_summary
    ),
    "case_record": case_record,

    "fail_closed": (
        not case_build_valid
        or context.get(
            "fail_closed",
            False,
        )
    ),
    "automated_response_allowed": False,
}

print(
    json.dumps(
        output,
        default=str,
    )
)
