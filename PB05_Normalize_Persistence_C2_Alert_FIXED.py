import hashlib
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


def pick(mapping, *names):
    if not isinstance(mapping, dict):
        return None

    normalized = {
        normalize_key(key): value
        for key, value in mapping.items()
    }

    for name in names:
        wanted = normalize_key(name)

        if wanted in normalized:
            value = normalized[wanted]

            if value not in (None, "", [], {}):
                return value

    return None


def as_text(value):
    value = decode_json(value)

    if value is None:
        return ""

    if isinstance(value, list):
        return ",".join(
            str(item).strip()
            for item in value
            if str(item).strip()
        )

    if isinstance(value, dict):
        return json.dumps(
            value,
            sort_keys=True,
            default=str,
        )

    return str(value).strip()


def normalize_account(value):
    account = as_text(value).strip()

    if "\\" in account:
        account = account.rsplit("\\", 1)[-1]

    if "@" in account:
        account = account.split("@", 1)[0]

    return account.strip().lower()


def account_domain(value):
    account = as_text(value).strip()

    if "\\" in account:
        return account.split("\\", 1)[0].upper()

    if "@" in account:
        return account.split("@", 1)[1].upper()

    return ""


def normalize_host(value):
    host = as_text(value).strip()

    if not host:
        return ""

    host = host.split(".", 1)[0]
    return host.upper()


def normalize_ip(value):
    address = as_text(value).strip()
    return re.sub(r"^::ffff:", "", address, flags=re.I)


def first_mapping(value):
    value = decode_json(value)

    if isinstance(value, dict):
        return value

    if isinstance(value, list):
        for item in value:
            item = decode_json(item)

            if isinstance(item, dict):
                return item

    return {}


raw_execution = decode_json(
    r'''$exec'''
)

root = first_mapping(raw_execution)

search_name = as_text(
    pick(
        root,
        "search_name",
        "savedsearch_name",
        "alert_name",
        "rule_name",
    )
)

payload = decode_json(
    pick(
        root,
        "result",
        "results",
        "body",
        "message",
        "data",
    )
)

row = first_mapping(payload)

if not row:
    row = root

nested_result = decode_json(
    pick(
        row,
        "result",
        "results",
        "body",
        "message",
        "data",
    )
)

if first_mapping(nested_result):
    row = first_mapping(nested_result)

if not search_name:
    search_name = as_text(
        pick(
            row,
            "search_name",
            "savedsearch_name",
            "alert_name",
            "rule_name",
        )
    )


explicit_detection_id = as_text(
    pick(
        row,
        "detection_id",
        "analytic_id",
        "rule_id",
    )
).upper()

detection_material = (
    explicit_detection_id
    + " "
    + search_name.upper()
)

if re.search(r"\bD17\b", detection_material):
    detection_id = "D17"
elif re.search(r"\bD18\b", detection_material):
    detection_id = "D18"
else:
    detection_id = ""


affected_user_raw = as_text(
    pick(
        row,
        "affected_user",
        "endpoint_user",
        "user",
        "username",
        "subject_user_name",
        "subject_username",
        "account_name",
        "account",
    )
)

process_path = as_text(
    pick(
        row,
        "process_path",
        "executable_path",
        "image",
        "new_process_name",
        "process_name",
        "chisel_path",
        "powershell_path",
    )
)

command_line = as_text(
    pick(
        row,
        "command_line",
        "process_command_line",
        "new_process_command_line",
        "chisel_command_line",
        "powershell_command_line",
    )
)

script_path = as_text(
    pick(
        row,
        "script_path",
        "powershell_script_path",
        "persistence_script",
    )
)

script_block_text = as_text(
    pick(
        row,
        "script_block_text",
        "scriptblock_text",
        "script_content",
        "powershell_script_block",
    )
)

if not affected_user_raw:
    user_path_material = " ".join([
        process_path,
        command_line,
        script_path,
        script_block_text,
    ])

    user_match = re.search(
        r"(?i)[a-z]:\\users\\([^\\\s\"']+)",
        user_path_material,
    )

    if user_match:
        affected_user_raw = user_match.group(1)


affected_user = normalize_account(
    affected_user_raw
)

affected_domain = account_domain(
    affected_user_raw
)

endpoint_host = normalize_host(
    pick(
        row,
        "endpoint_host",
        "endpoint_hostname",
        "computer_name",
        "computer",
        "workstation_name",
        "dest_host",
        "destination_host",
        "host",
    )
)

endpoint_address = normalize_ip(
    pick(
        row,
        "endpoint_address",
        "endpoint_ip",
        "source_address",
        "src_ip",
        "net_src_ip",
        "client_address",
    )
)

user_sid = as_text(
    pick(
        row,
        "user_sid",
        "subject_user_sid",
        "security_id",
        "sid",
    )
)

process_id = as_text(
    pick(
        row,
        "process_id",
        "pid",
        "new_process_id",
        "chisel_process_id",
        "endpoint_process_id",
    )
)

parent_process_id = as_text(
    pick(
        row,
        "parent_process_id",
        "parent_pid",
        "creator_process_id",
        "process_parent_id",
    )
)

parent_process_path = as_text(
    pick(
        row,
        "parent_process_path",
        "parent_process_name",
        "creator_process_name",
        "parent_image",
    )
)

process_creation_time = as_text(
    pick(
        row,
        "process_creation_time",
        "process_start_time",
        "process_event_time",
        "process_time",
        "event_time",
    )
)

run_key_path = as_text(
    pick(
        row,
        "run_key_path",
        "registry_path",
        "registry_key",
        "persistence_key",
    )
)

run_value_name = as_text(
    pick(
        row,
        "run_value_name",
        "registry_value_name",
        "value_name",
    )
)

run_value_data = as_text(
    pick(
        row,
        "run_value_data",
        "registry_value_data",
        "value_data",
    )
)

callback_address = normalize_ip(
    pick(
        row,
        "callback_address",
        "callback_ip",
        "external_peer",
        "destination_address",
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "net_dst_ip",
        "net_dest_ip",
        "server_ip",
    )
)

callback_port = as_text(
    pick(
        row,
        "callback_port",
        "destination_port",
        "dest_port",
        "dst_port",
        "net_dst_port",
        "net_dest_port",
        "server_port",
    )
)

network_material = " ".join([
    command_line,
    script_block_text,
])

if not callback_address:
    ip_match = re.search(
        r"(?<!\d)"
        r"((?:\d{1,3}\.){3}\d{1,3})"
        r"(?::(\d{1,5}))?",
        network_material,
    )

    if ip_match:
        callback_address = ip_match.group(1)

        if not callback_port and ip_match.group(2):
            callback_port = ip_match.group(2)


first_seen = as_text(
    pick(
        row,
        "first_seen",
        "first_time",
        "earliest_time",
    )
)

last_seen = as_text(
    pick(
        row,
        "last_seen",
        "last_time",
        "latest_time",
        "_time",
    )
)

event_time = as_text(
    pick(
        row,
        "event_time",
        "_time",
        "process_event_time",
    )
)

flow_id = as_text(
    pick(
        row,
        "flow_id",
        "network_flow_id",
        "suricata_flow_id",
    )
)

flow_duration = as_text(
    pick(
        row,
        "flow_duration",
        "duration",
        "flow_age",
    )
)

connection_count = as_text(
    pick(
        row,
        "connection_count",
        "connections",
        "connection_total",
        "flow_count",
    )
)

reconnect_count = as_text(
    pick(
        row,
        "reconnect_count",
        "reconnections",
        "reconnects",
        "callback_reconnect_count",
        "tunnel_reconnect_count",
    )
)

bytes_to_server = as_text(
    pick(
        row,
        "bytes_to_server",
        "toserver_bytes",
        "bytes_out",
    )
)

bytes_to_client = as_text(
    pick(
        row,
        "bytes_to_client",
        "toclient_bytes",
        "bytes_in",
    )
)

analytic_confidence = as_text(
    pick(
        row,
        "analytic_confidence",
        "confidence",
    )
)

detection_reason = as_text(
    pick(
        row,
        "detection_reason",
        "reason",
        "description",
    )
)

mitre_technique = as_text(
    pick(
        row,
        "mitre_technique",
        "mitre_techniques",
        "technique",
    )
)

alert_sid = as_text(
    pick(
        root,
        "sid",
        "alert_sid",
        "search_id",
    )
) or as_text(
    pick(
        row,
        "sid",
        "alert_sid",
        "search_id",
    )
)

detection_key = as_text(
    pick(
        row,
        "detection_key",
        "correlation_key",
        "alert_key",
    )
)

if not detection_key:
    detection_key = "|".join([
        endpoint_host or "UNKNOWN_HOST",
        affected_user or "UNKNOWN_USER",
        callback_address or "NO_CALLBACK",
        process_path or "NO_PROCESS_PATH",
    ])


supported_alert = detection_id in (
    "D17",
    "D18",
)

initial_attack_stage = {
    "D17": "P2",
    "D18": "P3",
}.get(
    detection_id,
    "UNSUPPORTED",
)

initial_hypothesis = {
    "D17": "PERSISTENCE_EXECUTION_HYPOTHESIS",
    "D18": "ACTIVE_C2_CHANNEL_HYPOTHESIS",
}.get(
    detection_id,
    "UNSUPPORTED_ALERT",
)

errors = []

if not supported_alert:
    errors.append(
        "UNSUPPORTED_DETECTION"
    )

if not endpoint_host:
    errors.append(
        "ENDPOINT_HOST_MISSING"
    )

if not affected_user:
    errors.append(
        "AFFECTED_USER_MISSING"
    )

if detection_id == "D18" and not callback_address:
    errors.append(
        "D18_CALLBACK_ADDRESS_MISSING"
    )

if detection_id == "D18" and not callback_port:
    errors.append(
        "D18_CALLBACK_PORT_MISSING"
    )


campaign_material = "|".join([
    endpoint_host or "UNKNOWN_HOST",
    affected_user or "UNKNOWN_USER",
])

campaign_digest = hashlib.sha256(
    campaign_material.encode("utf-8")
).hexdigest()[:16].upper()

campaign_id = (
    "PB05-CMP-"
    + campaign_digest
)

case_id = (
    "PB05-CASE-"
    + campaign_digest
)

normalized_at = (
    datetime.now(timezone.utc)
    .isoformat()
    .replace("+00:00", "Z")
)

normalization_valid = (
    supported_alert
    and len(errors) == 0
)

output = {
    "schema_version": "PB05-1.0",
    "playbook_id": "PB05",

    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,
    "campaign_key_basis": "ENDPOINT_HOST_AND_AFFECTED_USER",

    "normalization_status": (
        "NORMALIZED"
        if normalization_valid
        else "FAILED_CLOSED"
    ),
    "normalization_valid": normalization_valid,
    "normalization_errors": errors,
    "supported_alert": supported_alert,
    "fail_closed": not normalization_valid,
    "automated_response_allowed": False,

    "detection_id": detection_id,
    "search_name": search_name,
    "alert_sid": alert_sid,
    "detection_key": detection_key,
    "analytic_confidence": analytic_confidence,
    "detection_reason": detection_reason,
    "mitre_technique": mitre_technique,

    "initial_attack_stage": initial_attack_stage,
    "attack_stage_hypothesis": initial_hypothesis,
    "final_attack_stage": "NOT_ASSESSED",
    "assessment_status": "NOT_STARTED",

    "endpoint_host": endpoint_host,
    "endpoint_address": endpoint_address,
    "affected_user_raw": affected_user_raw,
    "affected_user": affected_user,
    "affected_domain": affected_domain,
    "user_sid": user_sid,

    "process_id": process_id,
    "parent_process_id": parent_process_id,
    "process_path": process_path,
    "parent_process_path": parent_process_path,
    "command_line": command_line,
    "process_creation_time": process_creation_time,

    "run_key_path": run_key_path,
    "run_value_name": run_value_name,
    "run_value_data": run_value_data,
    "script_path": script_path,
    "script_block_text": script_block_text,

    "callback_address": callback_address,
    "callback_port": callback_port,
    "flow_id": flow_id,
    "flow_duration": flow_duration,
    "connection_count": connection_count,
    "reconnect_count": reconnect_count,
    "bytes_to_server": bytes_to_server,
    "bytes_to_client": bytes_to_client,

    "event_time": event_time,
    "first_seen": first_seen,
    "last_seen": last_seen,

    "authorization_status": "NOT_EVALUATED",
    "authorized_test": False,
    "risk_score": None,
    "risk_level": "NOT_CALCULATED",
    "priority": "NOT_CALCULATED",
    "response_profile": "NOT_SELECTED",
    "approved_actions": [],
    "verification_status": "NOT_STARTED",
    "case_status": "NEW",

    "evidence_references": [
        {
            "detection_id": detection_id,
            "search_name": search_name,
            "alert_sid": alert_sid,
            "detection_key": detection_key,
            "event_time": event_time,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "connection_count": connection_count,
            "reconnect_count": reconnect_count,
        }
    ],

    "normalized_at": normalized_at,
}

print(
    json.dumps(
        output,
        default=str,
    )
)
