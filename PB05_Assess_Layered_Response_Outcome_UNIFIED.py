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


def unwrap_message(value):
    parsed = decode_json(value)
    if not isinstance(parsed, dict):
        return {}
    if "message" in parsed:
        message = decode_json(parsed.get("message"))
        if isinstance(message, dict):
            return message
    return parsed


def as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {
        "true", "1", "yes", "passed", "verified"
    }


def normalize_token(value):
    return re.sub(
        r"[^A-Z0-9]+", "_", str(value or "").strip().upper()
    ).strip("_")


def normalize_actions(value):
    parsed = decode_json(value)
    if not isinstance(parsed, list):
        return []
    actions = []
    for item in parsed:
        action = normalize_token(item)
        if action and action not in actions:
            actions.append(action)
    return actions


decision_validation = unwrap_message(
    r'''$validate_pb05_analyst_decision'''
)

plan = unwrap_message(r'''$build_pb05_approved_action_plan''')
block = unwrap_message(r'''$validate_pb05_c2_destination_block''')
pf_state = unwrap_message(r'''$validate_pb05_pf_state_termination''')
process_stop = unwrap_message(r'''$stop_verified_pb05_process''')
run_removal = unwrap_message(r'''$remove_verified_pb05_run_value''')
endpoint_verify = unwrap_message(r'''$verify_pb05_endpoint_state''')

def build_non_execution_outcome(validation):
    route = normalize_token(validation.get("decision_route"))

    route_map = {
        "FINALIZE_MONITORING": {
            "response_outcome": "MONITORING_ACCEPTED",
            "case_status": "CLOSED_MONITORING",
            "follow_up": [
                "CONTINUE_ENDPOINT_AND_NETWORK_MONITORING",
                "PRESERVE_AVAILABLE_EVIDENCE"
            ]
        },
        "FINALIZE_REJECTED": {
            "response_outcome": "RESPONSE_REJECTED",
            "case_status": "CLOSED_REJECTED",
            "follow_up": [
                "PRESERVE_AVAILABLE_EVIDENCE",
                "RECORD_REJECTION_RATIONALE"
            ]
        },
        "FINALIZE_FALSE_POSITIVE": {
            "response_outcome": "FALSE_POSITIVE_RECORDED",
            "case_status": "CLOSED_FALSE_POSITIVE",
            "follow_up": [
                "DOCUMENT_FALSE_POSITIVE_RATIONALE",
                "REVIEW_DETECTION_TUNING"
            ]
        },
        "FINALIZE_ESCALATED": {
            "response_outcome": "ESCALATED_TO_MANUAL_RESPONSE",
            "case_status": "ESCALATED_MANUAL_RESPONSE",
            "follow_up": [
                "PRESERVE_AVAILABLE_EVIDENCE",
                "PERFORM_MANUAL_ENDPOINT_INVESTIGATION",
                "PERFORM_MANUAL_NETWORK_INVESTIGATION"
            ]
        }
    }

    selected = route_map.get(route)

    if selected is None:
        selected = {
            "response_outcome": "FAILED_CLOSED",
            "case_status": "RESPONSE_VALIDATION_FAILED",
            "follow_up": [
                "REVIEW_INVALID_NON_EXECUTION_ROUTE"
            ]
        }

    persisted_case = decode_json(
        validation.get("persisted_case_record")
    )

    if not isinstance(persisted_case, dict):
        persisted_case = {}

    entities = decode_json(persisted_case.get("entities"))

    if not isinstance(entities, dict):
        entities = {}

    risk = decode_json(persisted_case.get("risk"))

    if not isinstance(risk, dict):
        risk = {}

    decision_record = decode_json(
        validation.get("decision_record")
    )

    if not isinstance(decision_record, dict):
        decision_record = {}

    case_id = str(
        validation.get("case_id")
        or persisted_case.get("case_id")
        or ""
    ).strip()

    campaign_id = str(
        validation.get("campaign_id")
        or persisted_case.get("campaign_id")
        or ""
    ).strip()

    case_lookup_key = str(
        validation.get("case_lookup_key")
        or persisted_case.get("case_lookup_key")
        or campaign_id
    ).strip()

    endpoint_host = str(
        entities.get("endpoint_host")
        or ""
    ).strip()

    affected_user = str(
        entities.get("affected_user")
        or ""
    ).strip()

    callback_address = str(
        entities.get("callback_address")
        or ""
    ).strip()

    callback_port = str(
        entities.get("callback_port")
        or ""
    ).strip()

    response_profile = str(
        validation.get("response_profile")
        or persisted_case.get("response_profile")
        or "CRP1"
    ).strip().upper()

    priority = str(
        risk.get("priority")
        or persisted_case.get("priority")
        or "P2"
    ).strip().upper()

    try:
        final_case_version = int(
            validation.get("case_version")
            or persisted_case.get("case_version")
            or 0
        ) + 1
    except Exception:
        final_case_version = (
            validation.get("case_version")
            or persisted_case.get("case_version")
            or 1
        )

    assessed_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    action_results = {
        "BLOCK_C2_DESTINATION": "NOT_REQUIRED",
        "TERMINATE_MATCHING_PF_STATES": "NOT_REQUIRED",
        "STOP_VERIFIED_PROCESS": "NOT_REQUIRED",
        "REMOVE_VERIFIED_RUN_VALUE": "NOT_REQUIRED"
    }

    response_outcome = selected["response_outcome"]
    case_status = selected["case_status"]
    required_follow_up = selected["follow_up"]

    summary_lines = [
        "PB05 FINAL RESPONSE",
        "",
        "Case ID: " + case_id,
        "Campaign ID: " + campaign_id,
        "Endpoint: " + endpoint_host,
        "Affected user: " + affected_user,
        "Callback: " + callback_address + ":" + callback_port,
        "Response profile: " + response_profile,
        "Analyst decision: " + str(
            decision_record.get("decision") or ""
        ),
        "Response outcome: " + response_outcome,
        "Case status: " + case_status,
        "Verification: NOT_REQUIRED",
        "",
        "No endpoint or firewall action was requested or executed.",
        "Required follow-up: " + ", ".join(required_follow_up)
    ]

    final_audit_record = {
        "schema_version": "PB05_FINAL_AUDIT_V1",
        "playbook_id": "PB05",
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_lookup_key": case_lookup_key,
        "case_version": final_case_version,
        "response_profile": response_profile,
        "analyst_decision": decision_record,
        "approved_actions": [],
        "action_results": action_results,
        "overall_containment": "NOT_EXECUTED",
        "verification_status": "NOT_REQUIRED",
        "response_outcome": response_outcome,
        "case_status": case_status,
        "issues": [],
        "required_follow_up": required_follow_up,
        "endpoint_action_performed": False,
        "network_action_performed": False,
        "binary_deletion_performed": False,
        "host_isolation_performed": False,
        "assessed_at": assessed_at
    }

    final_case_record = dict(persisted_case)

    final_response = decode_json(
        final_case_record.get("response")
    )

    if not isinstance(final_response, dict):
        final_response = {}

    final_response.update({
        "approved_actions": [],
        "action_results": action_results,
        "overall_containment": "NOT_EXECUTED",
        "verification_status": "NOT_REQUIRED",
        "response_outcome": response_outcome,
        "issues": [],
        "required_follow_up": required_follow_up,
        "endpoint_action_performed": False,
        "network_action_performed": False,
        "binary_deletion_performed": False,
        "host_isolation_performed": False,
        "final_response_at": assessed_at
    })

    analyst_decision_record = decode_json(
        final_case_record.get("analyst_decision")
    )

    if not isinstance(analyst_decision_record, dict):
        analyst_decision_record = {}

    analyst_decision_record.update({
        "required": False,
        "status": "COMPLETED",
        "decision_id": decision_record.get("decision_id", ""),
        "decision": decision_record.get("decision", ""),
        "approved_actions": [],
        "analyst_identity": decision_record.get(
            "analyst_identity",
            ""
        ),
        "decision_time": decision_record.get(
            "decision_time",
            ""
        ),
        "analyst_note": decision_record.get(
            "analyst_note",
            ""
        ),
        "validation_status": decision_record.get(
            "validation_status",
            "VALID"
        )
    })

    final_case_record.update({
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_lookup_key": case_lookup_key,
        "case_version": final_case_version,
        "case_status": case_status,
        "analyst_decision": analyst_decision_record,
        "response": final_response,
        "verification_status": "NOT_REQUIRED",
        "response_outcome": response_outcome,
        "final_audit_category": "pb05_endpoint_response_audit",
        "final_audit_key": case_lookup_key,
        "updated_at": assessed_at
    })

    return {
        "schema_version": "PB05_RESPONSE_ASSESSMENT_V1",
        "playbook_id": "PB05",
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_lookup_key": case_lookup_key,
        "case_version": final_case_version,
        "target_host": endpoint_host,
        "affected_user": affected_user,
        "callback_address": callback_address,
        "callback_port": callback_port,
        "response_profile": response_profile,
        "approved_actions": [],
        "action_results": action_results,
        "endpoint_containment_status": "NOT_REQUIRED",
        "process_restart": "NOT_EVALUATED",
        "callback_restart": "NOT_EVALUATED",
        "overall_containment": "NOT_EXECUTED",
        "verification_status": "NOT_REQUIRED",
        "response_outcome": response_outcome,
        "case_status": case_status,
        "issues": [],
        "required_follow_up": required_follow_up,
        "final_route": "PERSIST_FINAL_AUDIT",
        "final_audit_record": final_audit_record,
        "final_case_record": final_case_record,
        "automated_response_allowed": False,
        "notification_type": "PB05_FINAL_RESPONSE_NOTIFICATION",
        "priority": priority,
        "subject": "[{}] PB05 {} - {}".format(
            priority,
            response_outcome,
            endpoint_host
        ),
        "html_body": (
            '<pre style="font-family:Arial,sans-serif;white-space:pre-wrap;">'
            + "\n".join(summary_lines)
            + "</pre>"
        ),
        "assessed_at": assessed_at
    }


def build_execution_outcome():
    approved_actions = normalize_actions(
        plan.get("approved_actions_ordered")
    )
    approved_set = set(approved_actions)

    block_ok = (
        block.get("network_block_verification_valid") is True
        and normalize_token(block.get("c2_destination_block_status")) == "VERIFIED"
    )

    pf_state_ok = (
        pf_state.get("pf_state_verification_valid") is True
        and normalize_token(pf_state.get("pf_state_termination_status")) == "VERIFIED"
        and int(pf_state.get("matching_state_count_after") or 0) == 0
    )

    process_stop_status = normalize_token(
        process_stop.get("process_stop_status")
    )
    process_stop_ok = (
        as_bool(process_stop.get("success"))
        and as_bool(process_stop.get("verified_absent"))
        and process_stop_status in {
            "STOPPED_AND_VERIFIED",
            "ALREADY_ABSENT"
        }
    )

    run_removal_status = normalize_token(
        run_removal.get("persistence_removal_status")
    )
    run_removal_ok = (
        as_bool(run_removal.get("success"))
        and as_bool(run_removal.get("verified_absent"))
        and run_removal_status in {
            "REMOVED_AND_VERIFIED",
            "ALREADY_ABSENT"
        }
    )

    endpoint_status = normalize_token(
        endpoint_verify.get("endpoint_containment_status")
    )
    endpoint_verification_ok = (
        as_bool(endpoint_verify.get("success"))
        and as_bool(endpoint_verify.get("tunnel_process_absent"))
        and as_bool(endpoint_verify.get("run_value_absent"))
        and endpoint_status == "VERIFIED"
    )

    control_checks = {
        "BLOCK_C2_DESTINATION": block_ok,
        "TERMINATE_MATCHING_PF_STATES": pf_state_ok,
        "STOP_VERIFIED_PROCESS": process_stop_ok,
        "REMOVE_VERIFIED_RUN_VALUE": run_removal_ok
    }

    action_results = {}
    required_results = []
    issues = []

    for action, passed in control_checks.items():
        if action not in approved_set:
            action_results[action] = "NOT_REQUIRED"
            continue
        status = "VERIFIED" if passed else "FAILED"
        action_results[action] = status
        required_results.append(passed)
        if not passed:
            issues.append(action + "_NOT_VERIFIED")

    endpoint_actions_requested = any(
        action in approved_set
        for action in {
            "STOP_VERIFIED_PROCESS",
            "REMOVE_VERIFIED_RUN_VALUE"
        }
    )

    if endpoint_actions_requested:
        required_results.append(endpoint_verification_ok)
        if not endpoint_verification_ok:
            issues.append("FINAL_ENDPOINT_STATE_NOT_VERIFIED")

    if normalize_token(endpoint_verify.get("process_restart")) == "OBSERVED":
        issues.append("TUNNEL_PROCESS_RESTART_OBSERVED")

    if normalize_token(endpoint_verify.get("callback_restart")) not in {
        "", "NOT_OBSERVED_AT_ENDPOINT"
    }:
        issues.append("CALLBACK_RESTART_POSSIBLE")

    plan_valid = plan.get("action_plan_valid") is True
    if not plan_valid:
        issues.append("ACTION_PLAN_NOT_VALID")

    if not approved_actions:
        issues.append("NO_APPROVED_ACTIONS")

    if plan_valid and required_results and all(required_results):
        overall_containment = "VERIFIED"
    elif any(required_results):
        overall_containment = "PARTIAL"
    else:
        overall_containment = "FAILED"

    case_status = {
        "VERIFIED": "CONTAINED_PENDING_REMEDIATION",
        "PARTIAL": "PARTIALLY_CONTAINED",
        "FAILED": "CONTAINMENT_FAILED"
    }[overall_containment]

    response_outcome = {
        "VERIFIED": "LAYERED_CONTAINMENT_VERIFIED",
        "PARTIAL": "LAYERED_CONTAINMENT_PARTIAL",
        "FAILED": "LAYERED_CONTAINMENT_FAILED"
    }[overall_containment]

    endpoint_request = decode_json(plan.get("endpoint_action_request"))
    if not isinstance(endpoint_request, dict):
        endpoint_request = {}

    network_request = decode_json(plan.get("network_action_request"))
    if not isinstance(network_request, dict):
        network_request = {}

    target_endpoint = decode_json(endpoint_request.get("target_endpoint"))
    if not isinstance(target_endpoint, dict):
        target_endpoint = {}

    target_identity = decode_json(endpoint_request.get("target_identity"))
    if not isinstance(target_identity, dict):
        target_identity = {}

    destination = decode_json(network_request.get("destination"))
    if not isinstance(destination, dict):
        destination = {}

    persisted_case = decode_json(plan.get("persisted_case_record"))
    if not isinstance(persisted_case, dict):
        persisted_case = {}

    risk = decode_json(persisted_case.get("risk"))
    if not isinstance(risk, dict):
        risk = {}

    priority = str(
        risk.get("priority")
        or persisted_case.get("priority")
        or "P2"
    ).strip().upper()

    case_id = str(plan.get("case_id") or "").strip()
    campaign_id = str(plan.get("campaign_id") or "").strip()
    endpoint_host = str(target_endpoint.get("host") or "").strip()
    affected_user = str(target_identity.get("user") or "").strip()
    callback_address = str(destination.get("address") or "").strip()
    callback_port = str(destination.get("port") or "").strip()
    assessed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        final_case_version = int(plan.get("case_version") or 0) + 1
    except Exception:
        final_case_version = plan.get("case_version")

    required_follow_up = [
        "PRESERVE_SCRIPT_AND_BINARY_FOR_FORENSIC_REVIEW",
        "MONITOR_FOR_PROCESS_OR_CALLBACK_RESTART",
        "COMPLETE_ENDPOINT_COMPROMISE_SCOPING"
    ]

    if overall_containment != "VERIFIED":
        required_follow_up.insert(0, "COMPLETE_FAILED_CONTROLS_MANUALLY")

    if normalize_token(plan.get("response_profile")) == "CRP4":
        required_follow_up.append("REVIEW_DEFERRED_HOST_ISOLATION")

    summary_lines = [
        "PB05 FINAL RESPONSE",
        "",
        "Case ID: " + case_id,
        "Campaign ID: " + campaign_id,
        "Endpoint: " + endpoint_host,
        "Affected user: " + affected_user,
        "Callback: " + callback_address + ":" + callback_port,
        "Response profile: " + str(plan.get("response_profile") or ""),
        "Overall containment: " + overall_containment,
        "Case status: " + case_status,
        "",
        "C2 destination block: " + action_results["BLOCK_C2_DESTINATION"],
        "PF state termination: " + action_results["TERMINATE_MATCHING_PF_STATES"],
        "Tunnel process stop: " + action_results["STOP_VERIFIED_PROCESS"],
        "Persistence removal: " + action_results["REMOVE_VERIFIED_RUN_VALUE"],
        "Endpoint final state: " + (
            "VERIFIED" if endpoint_verification_ok else "FAILED"
        ),
        "Process restart: " + str(endpoint_verify.get("process_restart") or "UNKNOWN"),
        "Callback restart: " + str(endpoint_verify.get("callback_restart") or "UNKNOWN"),
        "",
        "Issues: " + (", ".join(issues) if issues else "None"),
        "Required follow-up: " + ", ".join(required_follow_up),
        "",
        "Binary deletion and automatic host isolation remain prohibited in PB05 v1."
    ]

    final_audit_record = {
        "schema_version": "PB05_FINAL_AUDIT_V1",
        "playbook_id": "PB05",
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_lookup_key": plan.get("case_lookup_key"),
        "case_version": plan.get("case_version"),
        "response_profile": plan.get("response_profile"),
        "approved_actions": approved_actions,
        "action_results": action_results,
        "endpoint_verification": endpoint_verify,
        "network_block_verification": block,
        "pf_state_verification": pf_state,
        "process_stop_result": process_stop,
        "persistence_removal_result": run_removal,
        "overall_containment": overall_containment,
        "response_outcome": response_outcome,
        "case_status": case_status,
        "issues": issues,
        "required_follow_up": required_follow_up,
        "binary_deletion_performed": False,
        "host_isolation_performed": False,
        "assessed_at": assessed_at
    }

    final_case_record = dict(persisted_case)
    final_response = decode_json(final_case_record.get("response"))
    if not isinstance(final_response, dict):
        final_response = {}

    final_response.update({
        "approved_actions": approved_actions,
        "action_results": action_results,
        "overall_containment": overall_containment,
        "verification_status": overall_containment,
        "response_outcome": response_outcome,
        "issues": issues,
        "required_follow_up": required_follow_up,
        "binary_deletion_performed": False,
        "host_isolation_performed": False,
        "final_response_at": assessed_at
    })

    final_case_record.update({
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_lookup_key": plan.get("case_lookup_key"),
        "case_version": final_case_version,
        "case_status": case_status,
        "response": final_response,
        "verification_status": overall_containment,
        "response_outcome": response_outcome,
        "final_audit_category": "pb05_endpoint_response_audit",
        "final_audit_key": plan.get("case_lookup_key"),
        "updated_at": assessed_at
    })

    output = {
        "schema_version": "PB05_RESPONSE_ASSESSMENT_V1",
        "playbook_id": "PB05",
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_lookup_key": plan.get("case_lookup_key"),
        "case_version": final_case_version,
        "target_host": endpoint_host,
        "affected_user": affected_user,
        "callback_address": callback_address,
        "callback_port": callback_port,
        "response_profile": plan.get("response_profile"),
        "approved_actions": approved_actions,
        "action_results": action_results,
        "endpoint_containment_status": (
            "VERIFIED" if endpoint_verification_ok else "FAILED"
        ),
        "process_restart": endpoint_verify.get("process_restart"),
        "callback_restart": endpoint_verify.get("callback_restart"),
        "overall_containment": overall_containment,
        "verification_status": overall_containment,
        "response_outcome": response_outcome,
        "case_status": case_status,
        "issues": issues,
        "required_follow_up": required_follow_up,
        "final_route": "PERSIST_FINAL_AUDIT",
        "final_audit_record": final_audit_record,
        "final_case_record": final_case_record,
        "automated_response_allowed": False,
        "notification_type": "PB05_FINAL_RESPONSE_NOTIFICATION",
        "priority": priority,
        "subject": "[{}] PB05 {} - {}".format(
            priority, overall_containment, endpoint_host
        ),
        "html_body": (
            '<pre style="font-family:Arial,sans-serif;white-space:pre-wrap;">'
            + "\n".join(summary_lines)
            + "</pre>"
        ),
        "assessed_at": assessed_at
    }

    return output


if (
    decision_validation.get("decision_validation_valid") is True
    and decision_validation.get("decision_is_non_execution") is True
):
    output = build_non_execution_outcome(
        decision_validation
    )
else:
    output = build_execution_outcome()

print(json.dumps(output))
