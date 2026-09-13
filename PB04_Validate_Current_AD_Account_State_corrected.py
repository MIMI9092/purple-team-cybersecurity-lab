import json
import re


def normalize_key(value):
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        str(value).lower(),
    ).strip("_")


def decode_json(value):
    current = value

    for _ in range(8):
        if not isinstance(current, str):
            break

        text = current.strip()

        if not text or text[0] not in "[{":
            break

        try:
            parsed = json.loads(text)
        except Exception:
            break

        if parsed == current:
            break

        current = parsed

    return current


def find_row(value, marker_fields):
    value = decode_json(value)

    if isinstance(value, dict):
        normalized_keys = {
            normalize_key(key)
            for key in value.keys()
        }

        if all(
            normalize_key(marker) in normalized_keys
            for marker in marker_fields
        ):
            return value

        for key in (
            "message",
            "body",
            "result",
            "results",
            "data",
            "content",
            "output",
            "value",
        ):
            if key not in value:
                continue

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
        return int(float(str(value).strip()))
    except Exception:
        return default


def as_list(value):
    value = decode_json(value)

    if value in (None, "", [], {}):
        return []

    if isinstance(value, list):
        return value

    return [value]


def action_list(value):
    normalized = []

    for item in as_list(value):
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


def get_ci(mapping, *names):
    if not isinstance(mapping, dict):
        return None

    lowered = {
        normalize_key(key): value
        for key, value in mapping.items()
    }

    for name in names:
        key = normalize_key(name)

        if key in lowered:
            return lowered[key]

    return None


def scalar(value):
    if isinstance(value, list):
        return value[0] if value else None

    return value


action_plan_output = decode_json(
    r'''$build_pb04_approved_action_plan'''
)

ad_state_output = decode_json(
    r'''$retrieve_current_ad_account_state'''
)

action_plan = find_row(
    action_plan_output,
    [
        "action_plan_status",
        "action_execution_route",
        "ad_action_request",
    ],
) or {}

ad_state = find_row(
    ad_state_output,
    ["attributes", "dn"],
) or {}

errors = []

case_id = str(
    action_plan.get("case_id", "")
).strip()

campaign_id = str(
    action_plan.get("campaign_id", "")
).strip()

target_account = normalized_account(
    action_plan.get("target_account")
)

action_plan_valid = to_bool(
    action_plan.get("action_plan_valid")
)

action_plan_status = str(
    action_plan.get("action_plan_status", "")
).strip().upper()

action_execution_route = str(
    action_plan.get("action_execution_route", "")
).strip().upper()

response_profile = str(
    action_plan.get("response_profile", "")
).strip().upper()

approved_actions = action_list(
    action_plan.get("approved_actions")
)

identity_action_authorized = to_bool(
    action_plan.get("identity_action_authorized")
)

account_disable_authorized = to_bool(
    action_plan.get(
        "account_disable_execution_authorized"
    )
)

requires_ad_interaction = to_bool(
    action_plan.get("requires_ad_interaction")
)

request = decode_json(
    action_plan.get("ad_action_request", {})
)

if not isinstance(request, dict):
    request = {}

requested_action = str(
    request.get("requested_action", "")
).strip().upper()

request_target = normalized_account(
    request.get("target_identity", {}).get(
        "account_name"
    )
    if isinstance(
        request.get("target_identity"),
        dict,
    )
    else ""
)

request_case_id = str(
    request.get("case_id", "")
).strip()

request_campaign_id = str(
    request.get("campaign_id", "")
).strip()

safety = decode_json(
    action_plan.get("current_asset_safety", {})
)

if not isinstance(safety, dict):
    safety = {}

if not action_plan:
    errors.append("ACTION_PLAN_UNAVAILABLE")

if not action_plan_valid:
    errors.append("ACTION_PLAN_INVALID")

if action_plan_status != "READY_FOR_AD_PRECHECK":
    errors.append(
        "ACTION_PLAN_NOT_READY_FOR_AD_PRECHECK"
    )

if action_execution_route != "RETRIEVE_CURRENT_AD_STATE":
    errors.append("ACTION_PLAN_ROUTE_INVALID")

if response_profile not in ("IRP3", "IRP4"):
    errors.append("RESPONSE_PROFILE_NOT_ELIGIBLE")

if approved_actions != ["TEMPORARY_ACCOUNT_DISABLE"]:
    errors.append("APPROVED_ACTION_SET_INVALID")

if not identity_action_authorized:
    errors.append("IDENTITY_ACTION_NOT_AUTHORIZED")

if not account_disable_authorized:
    errors.append("ACCOUNT_DISABLE_NOT_AUTHORIZED")

if not requires_ad_interaction:
    errors.append("AD_INTERACTION_NOT_REQUIRED_BY_PLAN")

if not case_id or not campaign_id:
    errors.append("CASE_OR_CAMPAIGN_ID_MISSING")

if request_case_id != case_id:
    errors.append("ACTION_REQUEST_CASE_ID_MISMATCH")

if request_campaign_id != campaign_id:
    errors.append("ACTION_REQUEST_CAMPAIGN_ID_MISMATCH")

if requested_action != "TEMPORARY_ACCOUNT_DISABLE":
    errors.append("ACTION_REQUEST_TYPE_INVALID")

if not target_account:
    errors.append("TARGET_ACCOUNT_MISSING")

if request_target != target_account:
    errors.append("ACTION_REQUEST_TARGET_MISMATCH")

if not to_bool(safety.get("identity_known")):
    errors.append("REFUSED_UNKNOWN_IDENTITY")

if str(
    safety.get("asset_lookup_status", "")
).strip().upper() != "IDENTITY_FOUND":
    errors.append("ASSET_LOOKUP_NOT_UNIQUE_OR_NOT_FOUND")

if to_int(safety.get("matching_asset_rows")) != 1:
    errors.append("NON_UNIQUE_ASSET_MATCH")

if to_bool(safety.get("privileged_account")):
    errors.append("REFUSED_PRIVILEGED_ACCOUNT")

if to_bool(safety.get("break_glass_account")):
    errors.append("REFUSED_BREAK_GLASS_ACCOUNT")

if not to_bool(safety.get("temporary_disable_allowed")):
    errors.append("TEMPORARY_DISABLE_NOT_ALLOWED")

if not to_bool(safety.get("temporary_disable_eligible")):
    errors.append("TEMPORARY_DISABLE_NOT_ELIGIBLE")

if str(
    safety.get("safety_revalidation_status", "")
).strip().upper() != "PASSED":
    errors.append("SAFETY_REVALIDATION_NOT_PASSED")

if not str(safety.get("recovery_method", "")).strip():
    errors.append("RECOVERY_METHOD_MISSING")

if not str(safety.get("recovery_owner", "")).strip():
    errors.append("RECOVERY_OWNER_MISSING")

attributes = decode_json(ad_state.get("attributes", {}))

if not isinstance(attributes, dict):
    attributes = {}

dn = str(ad_state.get("dn", "")).strip()

actual_account = normalized_account(
    scalar(
        get_ci(
            attributes,
            "sAMAccountName",
            "samaccountname",
        )
    )
)

if not attributes or not dn:
    errors.append("LIVE_AD_ACCOUNT_STATE_UNAVAILABLE")

if not actual_account:
    errors.append("LIVE_AD_ACCOUNT_NAME_MISSING")

if actual_account != target_account:
    errors.append("LIVE_AD_ACCOUNT_IDENTITY_MISMATCH")

if actual_account.endswith("$"):
    errors.append("REFUSED_MACHINE_ACCOUNT")

raw_uac = get_ci(
    attributes,
    "userAccountControl",
    "user_account_control",
)

uac_flags = []
uac_number = None

for item in as_list(raw_uac):
    text = str(item).strip()

    if not text:
        continue

    try:
        number = int(text)
    except Exception:
        number = None

    if number is not None:
        uac_number = number
    else:
        flag = re.sub(
            r"[^A-Z0-9]+",
            "_",
            text.upper(),
        ).strip("_")

        if flag and flag not in uac_flags:
            uac_flags.append(flag)

if raw_uac in (None, "", [], {}):
    errors.append("LIVE_AD_USER_ACCOUNT_CONTROL_MISSING")

account_disabled = (
    "ACCOUNTDISABLED" in uac_flags
    or "ACCOUNT_DISABLED" in uac_flags
    or (
        uac_number is not None
        and bool(uac_number & 0x0002)
    )
)

unsafe_account_flags = {
    "WORKSTATION_TRUST_ACCOUNT",
    "SERVER_TRUST_ACCOUNT",
    "INTERDOMAIN_TRUST_ACCOUNT",
}

if unsafe_account_flags.intersection(uac_flags):
    errors.append("REFUSED_UNSAFE_AD_ACCOUNT_TYPE")

if errors:
    precheck_status = "BLOCKED"
    execution_route = "STOP_FAIL_CLOSED"
    reason = "Live AD safety validation blocked the response."
elif account_disabled:
    precheck_status = "PASSED"
    execution_route = "VERIFY_EXISTING_DISABLED_STATE"
    reason = "Target account is already disabled; no duplicate disable will run."
else:
    precheck_status = "PASSED"
    execution_route = "EXECUTE_AD_DISABLE"
    reason = "Live AD identity and safety checks passed."

output = {
    "schema_version": "PB04_AD_PRECHECK_V1",
    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_version": action_plan.get("case_version"),
    "target_account": target_account,
    "response_profile": response_profile,
    "precheck_status": precheck_status,
    "execution_route": execution_route,
    "reason": reason,
    "failed_checks": errors,
    "account_disabled_before_response": account_disabled,
    "ad_state_before": {
        "samaccountname": actual_account,
        "distinguished_name": dn,
        "user_account_control_flags": uac_flags,
        "user_account_control_value": uac_number,
    },
    "ad_action_request": request,
    "identity_action_authorized": (
        not errors
        and identity_action_authorized
        and account_disable_authorized
    ),
    "automated_response_allowed": False,
}

print(json.dumps(output))
