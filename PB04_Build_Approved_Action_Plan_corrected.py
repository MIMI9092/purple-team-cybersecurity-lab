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


def to_bool(value):
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


def to_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def ensure_action_list(value):
    value = decode_json(value)

    if value in (None, "", [], {}):
        return []

    if isinstance(value, list):
        items = value
    else:
        items = re.split(
            r"[,;\n]+",
            str(value),
        )

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


def normalized_account(value):
    account = str(value or "").strip().lower()

    if "\\" in account:
        account = account.rsplit("\\", 1)[-1]

    if "@" in account:
        account = account.split("@", 1)[0]

    return account


decision_output = decode_json(
    r'''$validate_pb04_analyst_decision'''
)

safety_output = decode_json(
    r'''$revalidate_pb04_identity_safety'''
)

decision = find_row(
    decision_output,
    [
        "decision_validation_valid",
        "approved_actions_validated",
        "persisted_case_record",
    ],
) or {}

safety_http = find_row(
    safety_output,
    [
        "success",
        "status",
        "body",
    ],
) or {}

safety = find_row(
    safety_output,
    [
        "safety_revalidation_status",
        "identity_safety_status",
        "temporary_disable_eligible",
    ],
) or {}

errors = []

if not to_bool(
    decision.get("decision_validation_valid")
):
    errors.append("ANALYST_DECISION_INVALID")

http_status = to_int(
    safety_http.get("status"),
    0,
)

if http_status != 200:
    errors.append(
        "SAFETY_REVALIDATION_HTTP_FAILED"
    )

if not safety:
    errors.append(
        "SAFETY_REVALIDATION_RESULT_MISSING"
    )

case_id = str(
    decision.get("case_id", "")
).strip()

campaign_id = str(
    decision.get("campaign_id", "")
).strip()

if not case_id:
    errors.append("CASE_ID_MISSING")

if not campaign_id:
    errors.append("CAMPAIGN_ID_MISSING")

if str(
    safety.get("runtime_case_id", "")
).strip() != case_id:
    errors.append("SAFETY_CASE_ID_MISMATCH")

if str(
    safety.get("runtime_campaign_id", "")
).strip() != campaign_id:
    errors.append(
        "SAFETY_CAMPAIGN_ID_MISMATCH"
    )

persisted_case = decode_json(
    decision.get("persisted_case_record", {})
)

if not isinstance(persisted_case, dict):
    persisted_case = {}
    errors.append(
        "PERSISTED_CASE_RECORD_INVALID"
    )

target_account = normalized_account(
    persisted_case.get("entities", {}).get(
        "target_account"
    )
)

revalidated_target = normalized_account(
    safety.get("runtime_target_account")
)

if not target_account:
    errors.append("TARGET_ACCOUNT_MISSING")

if target_account != revalidated_target:
    errors.append(
        "TARGET_ACCOUNT_REVALIDATION_MISMATCH"
    )

response_profile = str(
    persisted_case.get("response", {}).get(
        "response_profile",
        "",
    )
).upper()

approved_actions = ensure_action_list(
    decision.get("approved_actions_validated")
)

decision_route = str(
    decision.get("decision_route", "")
).upper()

decision_is_non_execution = to_bool(
    decision.get("decision_is_non_execution")
)

decision_authorizes_identity_action = to_bool(
    decision.get(
        "decision_authorizes_identity_action"
    )
)

if (
    decision_is_non_execution
    and decision_authorizes_identity_action
):
    errors.append(
        "CONFLICTING_DECISION_EXECUTION_FLAGS"
    )

if (
    not decision_is_non_execution
    and not decision_authorizes_identity_action
):
    errors.append(
        "DECISION_EXECUTION_ROUTE_UNDETERMINED"
    )

identity_known = to_bool(
    safety.get("identity_known")
)

asset_lookup_status = str(
    safety.get("asset_lookup_status", "")
).upper()

matching_asset_rows = to_int(
    safety.get("matching_asset_rows")
)

privileged_account = to_bool(
    safety.get("privileged_normalized")
)

break_glass_account = to_bool(
    safety.get("break_glass_normalized")
)

temporary_disable_allowed = to_bool(
    safety.get("temporary_disable_normalized")
)

temporary_disable_eligible = to_bool(
    safety.get("temporary_disable_eligible")
)

safety_status = str(
    safety.get("safety_revalidation_status", "")
).upper()

identity_safety_status = str(
    safety.get("identity_safety_status", "")
).upper()

account_type = str(
    safety.get("account_type", "UNKNOWN")
).upper()

service_dependencies = str(
    safety.get("service_dependencies", "")
).strip()

dependency_review_required = to_bool(
    safety.get("dependency_review_normalized")
)

recovery_method = str(
    safety.get("recovery_method", "")
).strip()

recovery_owner = str(
    safety.get("recovery_owner", "")
).strip()

account_domain = str(
    safety.get("domain", "")
).strip()

current_asset_safety = {
    "identity_known": identity_known,
    "asset_lookup_status": asset_lookup_status,
    "matching_asset_rows": matching_asset_rows,
    "account_name": safety.get(
        "account_name",
        target_account,
    ),
    "domain": account_domain,
    "account_type": account_type,
    "business_criticality": safety.get(
        "business_criticality",
        "UNKNOWN",
    ),
    "privileged_account": privileged_account,
    "break_glass_account": break_glass_account,
    "temporary_disable_allowed": (
        temporary_disable_allowed
    ),
    "temporary_disable_eligible": (
        temporary_disable_eligible
    ),
    "dependency_review_required": (
        dependency_review_required
    ),
    "service_dependencies": service_dependencies,
    "recovery_method": recovery_method,
    "recovery_owner": recovery_owner,
    "identity_safety_status": (
        identity_safety_status
    ),
    "safety_revalidation_status": safety_status,
    "credential_rotation_status": safety.get(
        "credential_rotation_status",
        "ROTATION_NOT_EVALUATED",
    ),
    "revalidated_at": safety.get(
        "revalidated_at",
        "",
    ),
}

# Additional controls apply only when the analyst decision requests
# an identity-changing action.
if decision_authorizes_identity_action:
    if decision_route != "EXECUTE_APPROVED_ACTIONS":
        errors.append(
            "DECISION_DOES_NOT_AUTHORIZE_EXECUTION"
        )

    authorization_status = str(
        persisted_case.get("authorization", {}).get(
            "authorization_status",
            "",
        )
    ).upper()

    authorized_test = to_bool(
        persisted_case.get("authorization", {}).get(
            "authorized_test"
        )
    )

    if (
        authorized_test
        or authorization_status
        == "AUTHORIZED_IN_SCOPE"
    ):
        errors.append(
            "REFUSED_AUTHORIZED_TEST_ACTIVITY"
        )

    if response_profile not in ("IRP3", "IRP4"):
        errors.append(
            "RESPONSE_PROFILE_DOES_NOT_ALLOW_ACCOUNT_DISABLE"
        )

    if approved_actions != [
        "TEMPORARY_ACCOUNT_DISABLE"
    ]:
        errors.append(
            "UNSUPPORTED_OR_AMBIGUOUS_APPROVED_ACTION_SET"
        )

    if not identity_known:
        errors.append("REFUSED_UNKNOWN_IDENTITY")

    if asset_lookup_status != "IDENTITY_FOUND":
        errors.append(
            "REFUSED_ASSET_LOOKUP_NOT_UNIQUE_OR_NOT_FOUND"
        )

    if matching_asset_rows != 1:
        errors.append(
            "REFUSED_NON_UNIQUE_IDENTITY_MATCH"
        )

    if privileged_account:
        errors.append("REFUSED_PRIVILEGED_ACCOUNT")

    if break_glass_account:
        errors.append("REFUSED_BREAK_GLASS_ACCOUNT")

    if not temporary_disable_allowed:
        errors.append(
            "REFUSED_TEMPORARY_DISABLE_NOT_ALLOWED"
        )

    if not temporary_disable_eligible:
        errors.append(
            identity_safety_status
            or "REFUSED_IDENTITY_NOT_ELIGIBLE"
        )

    if safety_status != "PASSED":
        errors.append(
            "SAFETY_REVALIDATION_DID_NOT_PASS"
        )

    if (
        account_type == "SERVICE_ACCOUNT"
        and dependency_review_required
        and not service_dependencies
    ):
        errors.append(
            "REFUSED_SERVICE_DEPENDENCIES_NOT_DOCUMENTED"
        )

    if not recovery_method:
        errors.append("RECOVERY_METHOD_MISSING")

    if not recovery_owner:
        errors.append("RECOVERY_OWNER_MISSING")

    if not account_domain:
        errors.append("ACCOUNT_DOMAIN_MISSING")

else:
    if approved_actions:
        errors.append(
            "NON_EXECUTION_DECISION_CONTAINS_ACTIONS"
        )

    valid_non_execution_routes = {
        "FINALIZE_REJECTED",
        "FINALIZE_FALSE_POSITIVE",
        "FINALIZE_ESCALATED",
        "FINALIZE_MONITORING",
        "FINALIZE_NO_ACTION",
    }

    if decision_route not in valid_non_execution_routes:
        errors.append(
            "INVALID_NON_EXECUTION_DECISION_ROUTE"
        )

action_plan_valid = len(errors) == 0

if action_plan_valid and decision_authorizes_identity_action:
    action_plan_status = "READY_FOR_AD_PRECHECK"
    action_execution_route = (
        "RETRIEVE_CURRENT_AD_STATE"
    )

elif action_plan_valid and decision_is_non_execution:
    action_plan_status = (
        "READY_FOR_NON_EXECUTION_FINALIZATION"
    )
    action_execution_route = decision_route

else:
    action_plan_status = "FAILED_CLOSED"
    action_execution_route = (
        "FINALIZE_SAFETY_REFUSAL"
    )

planned_at = (
    datetime.now(timezone.utc)
    .isoformat()
    .replace("+00:00", "Z")
)

decision_record = decode_json(
    decision.get("decision_record", {})
)

if not isinstance(decision_record, dict):
    decision_record = {}

ad_action_request = {}

if action_plan_valid and decision_authorizes_identity_action:
    ad_action_request = {
        "schema_version": "PB04_AD_ACTION_PLAN_V1",
        "playbook_id": "PB04",
        "case_id": case_id,
        "campaign_id": campaign_id,
        "case_version": decision.get("case_version"),
        "requested_action": (
            "TEMPORARY_ACCOUNT_DISABLE"
        ),
        "approved_actions": approved_actions,
        "target_identity": {
            "account_name": target_account,
            "domain": account_domain,
            "account_type": account_type,
        },
        "analyst_decision": {
            "decision": decision.get(
                "analyst_decision",
                "",
            ),
            "analyst_identity": decision.get(
                "analyst_identity",
                "",
            ),
            "decision_time": decision.get(
                "analyst_decision_time",
                "",
            ),
            "analyst_note": decision.get(
                "analyst_note",
                "",
            ),
        },
        "safety_revalidation": current_asset_safety,
        "recovery": {
            "method": recovery_method,
            "owner": recovery_owner,
        },
        "expected_post_action_state": {
            "account_enabled": False,
        },
        "verification_required": True,
        "credential_rotation": {
            "recommended": True,
            "automation_allowed": False,
            "status": safety.get(
                "credential_rotation_status",
                "ROTATION_DEFERRED_PB04_V1_NO_ID03",
            ),
        },
        "persisted_case_record": persisted_case,
        "planned_at": planned_at,
    }

output = {
    "action_plan_valid": action_plan_valid,
    "action_plan_status": action_plan_status,
    "action_plan_errors": errors,
    "action_execution_route": (
        action_execution_route
    ),
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_version": decision.get("case_version"),
    "response_profile": response_profile,
    "target_account": target_account,
    "account_domain": account_domain,
    "account_type": account_type,
    "approved_actions": (
        approved_actions
        if action_plan_valid
        else []
    ),
    "analyst_decision": decision.get(
        "analyst_decision",
        "",
    ),
    "decision_route": decision_route,
    "decision_is_non_execution": (
        decision_is_non_execution
    ),
    "analyst_decision_record": decision_record,
    "current_asset_safety": current_asset_safety,
    "persisted_case_record": persisted_case,
    "ad_action_request": ad_action_request,
    "account_disable_execution_authorized": (
        action_plan_valid
        and decision_authorizes_identity_action
    ),
    "identity_action_authorized": (
        action_plan_valid
        and decision_authorizes_identity_action
    ),
    "requires_ad_interaction": (
        action_plan_valid
        and decision_authorizes_identity_action
    ),
    "non_execution_finalization": (
        action_plan_valid
        and decision_is_non_execution
    ),
    "credential_rotation_automation_allowed": False,
    "general_automation_allowed": False,
    "automated_response_allowed": False,
    "planned_at": planned_at,
}

print(json.dumps(output))
