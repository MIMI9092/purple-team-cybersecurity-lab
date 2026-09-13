import ast
import json


def parse_jsonish(value):
    current = value

    for _ in range(6):
        if isinstance(current, (dict, list)):
            return current

        if current is None:
            return {}

        text = str(current).strip()
        if not text:
            return {}

        try:
            parsed = json.loads(text)
        except Exception:
            parsed_lines = []

            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed_lines.append(json.loads(line))
                except Exception:
                    pass

            if parsed_lines:
                parsed = (
                    parsed_lines[0]
                    if len(parsed_lines) == 1
                    else parsed_lines
                )
            else:
                try:
                    parsed = ast.literal_eval(text)
                except Exception:
                    return {"_raw": text}

        if parsed == current:
            return parsed

        current = parsed

    return current


def unwrap(value, expected_key):
    current = parse_jsonish(value)

    for _ in range(6):
        if isinstance(current, list):
            matches = [
                item
                for item in current
                if isinstance(item, dict)
                and expected_key in item
            ]

            if matches:
                return matches[-1]

            nested_results = [
                item.get("result")
                for item in current
                if isinstance(item, dict)
                and "result" in item
            ]

            if nested_results:
                current = parse_jsonish(nested_results[-1])
                continue

            return current

        if not isinstance(current, dict):
            return current

        if expected_key in current:
            return current

        moved = False

        for key in ("message", "body", "data", "result"):
            if key not in current:
                continue

            candidate = parse_jsonish(current.get(key))

            if isinstance(candidate, (dict, list)):
                current = candidate
                moved = True
                break

        if not moved:
            return current

    return current


def get_ci(mapping, *names):
    if not isinstance(mapping, dict):
        return None

    lowered = {
        str(key).lower(): value
        for key, value in mapping.items()
    }

    for name in names:
        if str(name).lower() in lowered:
            return lowered[str(name).lower()]

    return None


def scalar(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_int(value, default=0):
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def as_bool(value):
    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in (
        "true",
        "1",
        "yes",
        "enabled",
        "passed",
        "success",
    )


def summarize_disable_response(raw_value):
    value = parse_jsonish(raw_value)

    for _ in range(4):
        if not isinstance(value, dict):
            break

        body = value.get("body")
        if body is not None:
            parsed_body = parse_jsonish(body)
            if isinstance(parsed_body, dict):
                value = parsed_body
                continue

        result_value = value.get("result")

        if isinstance(result_value, (dict, list)):
            value = result_value
            continue

        if isinstance(result_value, str):
            parsed_result = parse_jsonish(result_value)
            if isinstance(parsed_result, dict):
                value = parsed_result
                continue

        break

    if not isinstance(value, dict):
        return {
            "available": False,
            "reported_success": None,
            "result_code": "",
            "status": "",
            "description": "",
            "message": ""
        }

    success_value = get_ci(value, "success")
    result_code = scalar(
        get_ci(value, "result", "result_code", "code")
    )
    status = str(
        scalar(get_ci(value, "status")) or ""
    ).strip()
    description = str(
        scalar(get_ci(value, "description")) or ""
    ).strip()
    message = str(
        scalar(get_ci(value, "message", "reason")) or ""
    ).strip()

    reported_success = None

    if isinstance(success_value, bool):
        reported_success = success_value
    elif str(success_value).strip().lower() in ("true", "success"):
        reported_success = True
    elif str(success_value).strip().lower() in ("false", "failed"):
        reported_success = False
    elif result_code is not None and str(result_code).strip() != "":
        reported_success = str(result_code).strip() in ("0", "0.0")
    elif status.lower() == "success":
        reported_success = True
    elif (
        "already disable" in description.lower()
        or description.lower() == "success"
    ):
        reported_success = True

    return {
        "available": True,
        "reported_success": reported_success,
        "result_code": (
            "" if result_code is None else str(result_code)
        ),
        "status": status,
        "description": description,
        "message": message
    }


def emit(value):
    print(json.dumps(value, separators=(",", ":"), default=str))


def main():
    action_plan_raw = r'''$build_pb04_approved_action_plan'''
    precheck_raw = r'''$validate_current_ad_account_state'''
    disable_raw = r'''$temporarily_disable_approved_ad_account'''
    post_state_raw = r'''$retrieve_ad_account_state_after_response'''
    authentication_raw = r'''$search_post_response_authentication_evidence'''

    action_plan = unwrap(
        action_plan_raw,
        "action_plan_valid",
    )

    if not isinstance(action_plan, dict):
        emit({
            "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
            "verification_status": "FAILED",
            "response_outcome": "BLOCKED_FAIL_CLOSED",
            "case_status": "RESPONSE_BLOCKED_REQUIRES_ANALYST",
            "final_route": "PERSIST_FINAL_AUDIT",
            "reason": "Approved action plan was unavailable.",
            "issues": ["ACTION_PLAN_UNAVAILABLE"],
            "identity_action_authorized": False,
            "automated_response_allowed": False,
        })
        return

    action_plan_valid = as_bool(
        action_plan.get("action_plan_valid")
    )

    if not action_plan_valid:
        emit({
            "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
            "case_id": action_plan.get("case_id", ""),
            "campaign_id": action_plan.get("campaign_id", ""),
            "target_account": action_plan.get(
                "target_account",
                "",
            ),
            "verification_status": "FAILED",
            "response_outcome": "BLOCKED_FAIL_CLOSED",
            "case_status": "RESPONSE_BLOCKED_REQUIRES_ANALYST",
            "final_route": "PERSIST_FINAL_AUDIT",
            "reason": "Approved action plan failed closed.",
            "issues": action_plan.get(
                "action_plan_errors",
                ["ACTION_PLAN_INVALID"],
            ),
            "identity_action_authorized": False,
            "automated_response_allowed": False,
        })
        return

    non_execution_finalization = as_bool(
        action_plan.get("non_execution_finalization")
    )

    requires_ad_interaction = as_bool(
        action_plan.get("requires_ad_interaction")
    )

    if non_execution_finalization:
        decision_route = str(
            action_plan.get(
                "action_execution_route",
                action_plan.get("decision_route", ""),
            )
        ).upper()

        route_outcomes = {
            "FINALIZE_MONITORING": {
                "response_outcome": "MONITORING_ACCEPTED",
                "case_status": "CLOSED_MONITORING",
                "required_follow_up": [
                    "CONTINUE_IDENTITY_MONITORING",
                    "COMPLETE_IDENTITY_DEPENDENCY_REVIEW",
                    "ROTATE_CREDENTIAL_USING_APPROVED_MANUAL_PROCEDURE",
                ],
            },
            "FINALIZE_REJECTED": {
                "response_outcome": "ANALYST_REJECTED_RESPONSE",
                "case_status": "CLOSED_RESPONSE_REJECTED",
                "required_follow_up": [
                    "DOCUMENT_ANALYST_REJECTION",
                ],
            },
            "FINALIZE_FALSE_POSITIVE": {
                "response_outcome": "FALSE_POSITIVE",
                "case_status": "CLOSED_FALSE_POSITIVE",
                "required_follow_up": [
                    "REVIEW_DETECTION_TUNING",
                ],
            },
            "FINALIZE_ESCALATED": {
                "response_outcome": "ESCALATED",
                "case_status": "ESCALATED_REQUIRES_MANUAL_RESPONSE",
                "required_follow_up": [
                    "CONTINUE_MANUAL_INCIDENT_RESPONSE",
                ],
            },
            "FINALIZE_NO_ACTION": {
                "response_outcome": "CLOSED_NO_ACTION",
                "case_status": "CLOSED_NO_ACTION",
                "required_follow_up": [],
            },
        }

        route_result = route_outcomes.get(decision_route)

        if route_result is None:
            emit({
                "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
                "case_id": action_plan.get("case_id", ""),
                "campaign_id": action_plan.get(
                    "campaign_id",
                    "",
                ),
                "target_account": action_plan.get(
                    "target_account",
                    "",
                ),
                "verification_status": "FAILED",
                "response_outcome": "BLOCKED_FAIL_CLOSED",
                "case_status": "RESPONSE_BLOCKED_REQUIRES_ANALYST",
                "final_route": "PERSIST_FINAL_AUDIT",
                "reason": "Invalid non-execution finalization route.",
                "issues": [
                    "INVALID_NON_EXECUTION_FINALIZATION_ROUTE"
                ],
                "identity_action_authorized": False,
                "automated_response_allowed": False,
            })
            return

        safety = parse_jsonish(
            action_plan.get("current_asset_safety", {})
        )

        if not isinstance(safety, dict):
            safety = {}

        emit({
            "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
            "case_id": action_plan.get("case_id", ""),
            "campaign_id": action_plan.get("campaign_id", ""),
            "case_version": action_plan.get("case_version"),
            "target_account": action_plan.get(
                "target_account",
                "",
            ),
            "analyst_decision": action_plan.get(
                "analyst_decision",
                "",
            ),
            "decision_route": decision_route,
            "verification_status": "NOT_REQUIRED",
            "response_outcome": route_result[
                "response_outcome"
            ],
            "case_status": route_result["case_status"],
            "final_route": "PERSIST_FINAL_AUDIT",
            "account_disable_status": "NOT_REQUESTED",
            "credential_rotation_status": safety.get(
                "credential_rotation_status",
                "RECOMMENDED_NOT_AUTOMATED",
            ),
            "authentication_status": (
                "NOT_REQUIRED_FOR_NON_EXECUTION_DECISION"
            ),
            "existing_sessions_status": "NOT_EVALUATED",
            "issues": [],
            "disable_action": {
                "attempted": False,
                "reported_result": {
                    "available": False,
                    "reported_success": None,
                    "result_code": "",
                    "status": "NOT_REQUESTED",
                    "description": (
                        "No identity-changing action was approved."
                    ),
                    "message": "",
                },
            },
            "ad_state_after": {
                "samaccountname": "",
                "distinguished_name": "",
                "account_disabled": False,
                "user_account_control_flags": [],
            },
            "authentication_evidence": {
                "available": False,
                "successful_authentication_events": 0,
                "failed_or_denied_events": 0,
                "explicit_credential_events": 0,
                "privileged_session_events": 0,
                "observation": (
                    "Not required for a non-execution decision."
                ),
                "source_addresses": [],
                "event_codes": [],
                "verification_caveat": (
                    "No AD action was requested or executed."
                ),
            },
            "required_follow_up": route_result[
                "required_follow_up"
            ],
            "ad_action_request": {},
            "analyst_decision_record": action_plan.get(
                "analyst_decision_record",
                {},
            ),
            "persisted_case_record": action_plan.get(
                "persisted_case_record",
                {},
            ),
            "no_ad_interaction_confirmed": True,
            "identity_action_authorized": False,
            "automated_response_allowed": False,
        })
        return

    if not requires_ad_interaction:
        emit({
            "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
            "case_id": action_plan.get("case_id", ""),
            "campaign_id": action_plan.get("campaign_id", ""),
            "target_account": action_plan.get(
                "target_account",
                "",
            ),
            "verification_status": "FAILED",
            "response_outcome": "BLOCKED_FAIL_CLOSED",
            "case_status": "RESPONSE_BLOCKED_REQUIRES_ANALYST",
            "final_route": "PERSIST_FINAL_AUDIT",
            "reason": (
                "Action plan has no valid finalization or AD route."
            ),
            "issues": ["ACTION_PLAN_ROUTE_INVALID"],
            "identity_action_authorized": False,
            "automated_response_allowed": False,
        })
        return

    precheck = unwrap(precheck_raw, "precheck_status")

    if not isinstance(precheck, dict):
        emit({
            "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
            "verification_status": "FAILED",
            "response_outcome": "BLOCKED_FAIL_CLOSED",
            "case_status": "RESPONSE_BLOCKED_REQUIRES_ANALYST",
            "final_route": "PERSIST_FINAL_AUDIT",
            "reason": "AD precheck result was unavailable."
        })
        return

    case_id = str(precheck.get("case_id", "")).strip()
    target_account = str(
        precheck.get("target_account", "")
    ).strip()
    precheck_status = str(
        precheck.get("precheck_status", "")
    ).strip().upper()
    execution_route = str(
        precheck.get("execution_route", "")
    ).strip().upper()

    request = parse_jsonish(
        precheck.get("ad_action_request", {})
    )

    if not isinstance(request, dict):
        request = {}

    if (
        precheck_status == "BLOCKED"
        or execution_route == "STOP_FAIL_CLOSED"
    ):
        emit({
            "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
            "case_id": case_id,
            "target_account": target_account,
            "verification_status": "FAILED",
            "response_outcome": "BLOCKED_FAIL_CLOSED",
            "case_status": "RESPONSE_BLOCKED_REQUIRES_ANALYST",
            "final_route": "PERSIST_FINAL_AUDIT",
            "reason": precheck.get(
                "reason",
                "Live AD safety validation blocked the response."
            ),
            "failed_checks": precheck.get("failed_checks", []),
            "account_disable_status": "NOT_EXECUTED",
            "credential_rotation_status": (
                "RECOMMENDED_NOT_AUTOMATED"
            ),
            "existing_sessions_status": (
                "REQUIRES_INVESTIGATION"
            ),
            "ad_action_request": request
        })
        return

    post_state = unwrap(post_state_raw, "attributes")
    authentication = unwrap(
        authentication_raw,
        "authentication_observation"
    )

    disable_attempted = (
        execution_route == "EXECUTE_AD_DISABLE"
    )

    disable_summary = summarize_disable_response(disable_raw)

    post_lookup_ok = (
        isinstance(post_state, dict)
        and isinstance(post_state.get("attributes"), dict)
        and post_state.get("success") is not False
    )

    actual_account = ""
    distinguished_name = ""
    flags = []

    if post_lookup_ok:
        attributes = post_state["attributes"]

        actual_account = str(
            scalar(
                get_ci(
                    attributes,
                    "sAMAccountName",
                    "samAccountName"
                )
            ) or ""
        ).strip()

        distinguished_name = str(
            post_state.get("dn", "")
        ).strip()

        flags = [
            str(item).strip().upper()
            for item in as_list(
                get_ci(attributes, "userAccountControl")
            )
            if str(item).strip()
        ]

    account_identity_matches = (
        bool(target_account)
        and bool(actual_account)
        and target_account.lower() == actual_account.lower()
    )

    account_disabled_after_response = (
        "ACCOUNTDISABLED" in flags
    )

    authentication_available = (
        isinstance(authentication, dict)
        and (
            "authentication_observation" in authentication
            or "total_authentication_events" in authentication
        )
    )

    successful_authentication_events = (
        as_int(
            authentication.get(
                "successful_authentication_events",
                0
            )
        )
        if authentication_available
        else 0
    )

    failed_or_denied_events = (
        as_int(
            authentication.get(
                "failed_or_denied_events",
                0
            )
        )
        if authentication_available
        else 0
    )

    explicit_credential_events = (
        as_int(
            authentication.get(
                "explicit_credential_events",
                0
            )
        )
        if authentication_available
        else 0
    )

    privileged_session_events = (
        as_int(
            authentication.get(
                "privileged_session_events",
                0
            )
        )
        if authentication_available
        else 0
    )

    issues = []

    if not post_lookup_ok:
        issues.append("POST_RESPONSE_AD_LOOKUP_FAILED")
    elif not account_identity_matches:
        issues.append("POST_RESPONSE_IDENTITY_MISMATCH")
    elif not flags:
        issues.append("POST_RESPONSE_ACCOUNT_STATE_UNKNOWN")
    elif not account_disabled_after_response:
        issues.append("ACCOUNT_NOT_DISABLED")

    if (
        disable_attempted
        and disable_summary["reported_success"] is False
    ):
        issues.append("DISABLE_ACTION_REPORTED_FAILURE")

    if not authentication_available:
        issues.append(
            "POST_RESPONSE_AUTHENTICATION_EVIDENCE_UNAVAILABLE"
        )
    elif successful_authentication_events > 0:
        issues.append(
            "SUCCESSFUL_AUTHENTICATION_OBSERVED_AFTER_RESPONSE"
        )

    if not post_lookup_ok or not account_identity_matches:
        verification_status = "FAILED"
        response_outcome = "FAILED"
        case_status = "RESPONSE_FAILED_REQUIRES_ANALYST"
        account_disable_status = "FAILED"
    elif not account_disabled_after_response:
        verification_status = "FAILED"
        response_outcome = "FAILED"
        case_status = "RESPONSE_FAILED_REQUIRES_ANALYST"
        account_disable_status = "FAILED"
    elif issues:
        verification_status = "PARTIAL"
        response_outcome = "PARTIAL_CONTAINMENT"
        case_status = "CONTAINED_PENDING_FOLLOWUP"
        account_disable_status = "VERIFIED"
    else:
        verification_status = "VERIFIED"

        if execution_route == "VERIFY_EXISTING_DISABLED_STATE":
            response_outcome = "NO_ACTION_REQUIRED"
            account_disable_status = "VERIFIED_ALREADY_DISABLED"
        else:
            response_outcome = "SUCCESS"
            account_disable_status = "VERIFIED"

        case_status = "CONTAINED_PENDING_REMEDIATION"

    if not authentication_available:
        authentication_status = "NOT_VERIFIED"
    elif successful_authentication_events > 0:
        authentication_status = (
            "SUCCESSFUL_AUTHENTICATION_OBSERVED"
        )
    elif failed_or_denied_events > 0:
        authentication_status = (
            "FAILED_OR_DENIED_ATTEMPTS_OBSERVED"
        )
    elif (
        explicit_credential_events > 0
        or privileged_session_events > 0
    ):
        authentication_status = (
            "SESSION_OR_CREDENTIAL_ACTIVITY_REQUIRES_REVIEW"
        )
    else:
        authentication_status = (
            "NO_NEW_AUTHENTICATION_EVIDENCE"
        )

    required_follow_up = [
        "INVESTIGATE_EXISTING_SESSIONS_AND_KERBEROS_TICKETS",
        "COMPLETE_IDENTITY_DEPENDENCY_REVIEW",
        "ROTATE_CREDENTIAL_USING_APPROVED_MANUAL_PROCEDURE"
    ]

    if successful_authentication_events > 0:
        required_follow_up.append(
            "URGENTLY_INVESTIGATE_POST_RESPONSE_AUTHENTICATION"
        )

    emit({
        "schema_version": "PB04_RESPONSE_ASSESSMENT_V1",
        "case_id": case_id,
        "target_account": target_account,
        "verification_status": verification_status,
        "response_outcome": response_outcome,
        "case_status": case_status,
        "final_route": "PERSIST_FINAL_AUDIT",
        "account_disable_status": account_disable_status,
        "credential_rotation_status": (
            "RECOMMENDED_NOT_AUTOMATED"
        ),
        "authentication_status": authentication_status,
        "existing_sessions_status": (
            "REQUIRES_INVESTIGATION"
        ),
        "issues": issues,
        "disable_action": {
            "attempted": disable_attempted,
            "reported_result": disable_summary
        },
        "ad_state_after": {
            "samaccountname": actual_account,
            "distinguished_name": distinguished_name,
            "account_disabled": account_disabled_after_response,
            "user_account_control_flags": flags
        },
        "authentication_evidence": {
            "available": authentication_available,
            "successful_authentication_events": (
                successful_authentication_events
            ),
            "failed_or_denied_events": failed_or_denied_events,
            "explicit_credential_events": (
                explicit_credential_events
            ),
            "privileged_session_events": (
                privileged_session_events
            ),
            "observation": (
                authentication.get(
                    "authentication_observation",
                    ""
                )
                if authentication_available
                else ""
            ),
            "source_addresses": (
                authentication.get("source_addresses", [])
                if authentication_available
                else []
            ),
            "event_codes": (
                authentication.get("event_codes", [])
                if authentication_available
                else []
            ),
            "verification_caveat": (
                "Disabling an account does not terminate "
                "already-issued Kerberos tickets or existing sessions."
            )
        },
        "required_follow_up": required_follow_up,
        "ad_action_request": request
    })


main()
