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

        raw = current.strip()

        if not raw:
            return {}

        try:
            current = json.loads(raw)
            continue
        except Exception:
            pass

        # Splunk export may return newline-delimited JSON containing
        # preview rows followed by a final row.
        decoded_lines = []

        for line in raw.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                decoded_lines.append(json.loads(line))
            except Exception:
                continue

        if decoded_lines:
            current = decoded_lines
            continue

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
                        return decode_json(
                            value[output_key]
                        )

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
            normalize_key(marker)
            in normalized_keys
            for marker in marker_fields
        ):
            return value

        for preferred_key in (
            "message",
            "body",
            "result",
            "results",
            "data",
            "content",
            "output",
        ):
            for key, child in value.items():
                if (
                    normalize_key(key)
                    == preferred_key
                ):
                    found = find_row(
                        child,
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


def text(value):
    if value is None:
        return ""

    return str(value).strip()


def parse_time(value):
    raw = text(value)

    if not raw:
        return None

    candidate = raw.replace(
        "Z",
        "+00:00",
    )

    try:
        parsed = datetime.fromisoformat(
            candidate
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )
    except Exception:
        pass

    for time_format in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
    ):
        try:
            return datetime.strptime(
                raw,
                time_format,
            ).replace(
                tzinfo=timezone.utc
            )
        except Exception:
            continue

    return None


def get_http_context(output, markers):
    http = find_row(
        output,
        [
            "status",
            "body",
            "url",
        ],
    ) or {}

    status = to_int(
        http.get("status"),
        0,
    )

    row = find_row(
        http.get("body"),
        markers,
    )

    if row is None:
        row = find_row(
            output,
            markers,
        )

    if not isinstance(row, dict):
        row = {}

    return http, status, row


# Read each upstream action explicitly. This is reliable in Shuffle
# even when self.full_execution does not contain named action results.
validation_output = decode_json(
    r'''$validate_supported_d17_d18_alert'''
)

existing_output = decode_json(
    r'''$check_for_existing_pb05_case'''
)

authorization_output = decode_json(
    r'''$validate_authorized_persistence_c2_scope'''
)

asset_output = decode_json(
    r'''$enrich_pb05_endpoint_asset_and_response_policy'''
)

persistence_output = decode_json(
    r'''$enrich_persistence_evidence'''
)

process_output = decode_json(
    r'''$enrich_process_and_powershell_evidence'''
)

network_output = decode_json(
    r'''$enrich_network_and_c2_evidence'''
)


validation = find_row(
    validation_output,
    [
        "alert_validation_valid",
        "detection_id",
        "case_id",
    ],
) or {}

existing_lookup = find_row(
    existing_output,
    [
        "found",
        "key",
        "value",
    ],
) or {}

authorization_http, authorization_status_code, authorization = (
    get_http_context(
        authorization_output,
        [
            "authorization_status",
            "scope_reason",
            "authorized_test",
        ],
    )
)

asset_http, asset_status_code, asset = get_http_context(
    asset_output,
    [
        "asset_lookup_status",
        "endpoint_response_policy_status",
        "endpoint_known",
    ],
)

persistence_http, persistence_status_code, persistence = (
    get_http_context(
        persistence_output,
        [
            "persistence_evidence_status",
            "total_persistence_events",
        ],
    )
)

process_http, process_status_code, process = get_http_context(
    process_output,
    [
        "process_evidence_status",
        "total_process_powershell_events",
    ],
)

network_http, network_status_code, network = get_http_context(
    network_output,
    [
        "network_evidence_status",
        "total_network_records",
    ],
)


# A successful Splunk export can legitimately contain no row. For D17, the
# validated source alert itself carries the exact process and persistence
# identity that will later be checked again against live endpoint state before
# any write. Preserve that alert evidence instead of treating an empty
# enrichment result as a transport/parser failure.
detection_id = text(
    validation.get("detection_id")
).upper()

source_callback_address = text(
    validation.get("callback_address")
)
source_callback_port = text(
    validation.get("callback_port")
)
source_callback = (
    source_callback_address
    + ":"
    + source_callback_port
)
source_process_id = text(
    validation.get("process_id")
)
source_process_path = text(
    validation.get("process_path")
)
source_process_command = text(
    validation.get("command_line")
)
source_process_created = text(
    validation.get("process_creation_time")
)
source_run_value_name = text(
    validation.get("run_value_name")
)
source_run_value_data = text(
    validation.get("run_value_data")
)
source_script_path = text(
    validation.get("script_path")
)
source_connection_count = to_int(
    validation.get("connection_count")
)
source_flow_duration = to_int(
    validation.get("flow_duration")
)
source_reconnect_count = to_int(
    validation.get("reconnect_count")
)
source_first_seen = text(
    validation.get("first_seen")
)
source_last_seen = text(
    validation.get("last_seen")
)

validated_d17_alert_evidence = all([
    to_bool(validation.get("alert_validation_valid")),
    detection_id == "D17",
    to_int(source_process_id) > 0,
    bool(source_process_created),
    source_process_path.lower().endswith("\\chisel.exe"),
    bool(source_callback_address),
    bool(source_callback_port),
    source_callback.lower() in source_process_command.lower(),
    "chisel.exe" in source_process_command.lower(),
    source_run_value_name.lower() == "pfa-lab-tunnel",
    bool(source_run_value_data),
    source_script_path.lower().endswith("\\pfa-tunnel.ps1"),
])

validated_d18_alert_evidence = all([
    to_bool(validation.get("alert_validation_valid")),
    detection_id == "D18",
    to_int(source_process_id) > 0,
    bool(source_process_created),
    source_process_path.lower().endswith("\\chisel.exe"),
    bool(source_callback_address),
    bool(source_callback_port),
    source_callback.lower() in source_process_command.lower(),
    "chisel.exe" in source_process_command.lower(),
    (
        source_connection_count > 0
        or source_flow_duration > 0
    ),
    bool(source_first_seen),
    bool(source_last_seen),
])

validated_endpoint_alert_evidence = (
    validated_d17_alert_evidence
    or validated_d18_alert_evidence
)

source_event_time = validation.get(
    "process_creation_time",
    validation.get(
        "first_seen",
        validation.get("event_time", ""),
    ),
)

use_source_persistence_fallback = (
    validated_endpoint_alert_evidence
    and (
        not persistence
        or (
            to_int(
                persistence.get(
                    "total_persistence_events"
                )
            )
            == 0
            and not to_bool(
                persistence.get(
                    "persistence_execution_supported"
                )
            )
        )
    )
)

if not persistence or use_source_persistence_fallback:
    persistence = {
        "runtime_case_id": validation.get("case_id", ""),
        "runtime_campaign_id": validation.get("campaign_id", ""),
        "runtime_host": validation.get("endpoint_host", ""),
        "runtime_user": validation.get("affected_user", ""),
        "persistence_evidence_status": (
            "VALIDATED_SOURCE_ALERT_PERSISTENCE_REPORTED"
            if validated_endpoint_alert_evidence
            else "NO_MATCHING_PERSISTENCE_EVIDENCE"
        ),
        "persistence_execution_supported": validated_endpoint_alert_evidence,
        "direct_registry_telemetry_status": (
            "SOURCE_ALERT_REPORTED_REQUIRES_LIVE_REVALIDATION"
            if validated_endpoint_alert_evidence
            else "DIRECT_REGISTRY_TELEMETRY_NOT_OBSERVED"
        ),
        "evidence_row_found": 0,
        "total_persistence_events": (
            1 if validated_endpoint_alert_evidence else 0
        ),
        "first_persistence_epoch": source_event_time,
        "persistence_signals": (
            ["VALIDATED_D17_RUN_VALUE_AND_SCRIPT"]
            if validated_d17_alert_evidence
            else ["VALIDATED_D18_PERSISTENCE_CONTEXT"]
            if validated_d18_alert_evidence
            else []
        ),
        "event_record_ids": [],
        "powershell_4104_count": 0,
        "security_registry_4657_count": 0,
        "sysmon_registry_13_count": 0,
    }

use_source_process_fallback = (
    validated_endpoint_alert_evidence
    and (
        not process
        or (
            to_int(
                process.get(
                    "total_process_powershell_events"
                )
            )
            == 0
            and to_int(
                process.get(
                    "tunnel_process_execution_count"
                )
            )
            == 0
        )
    )
)

if not process or use_source_process_fallback:
    reverse_socks_reported = (
        validated_endpoint_alert_evidence
        and "r:" in source_process_command.lower()
        and "socks" in source_process_command.lower()
    )
    process = {
        "runtime_case_id": validation.get("case_id", ""),
        "runtime_campaign_id": validation.get("campaign_id", ""),
        "runtime_host": validation.get("endpoint_host", ""),
        "runtime_user": validation.get("affected_user", ""),
        "process_evidence_status": (
            "VALIDATED_SOURCE_ALERT_TUNNEL_PROCESS_REPORTED"
            if validated_endpoint_alert_evidence
            else "NO_MATCHING_PROCESS_EVIDENCE"
        ),
        "evidence_row_found": 0,
        "total_process_powershell_events": (
            1 if validated_endpoint_alert_evidence else 0
        ),
        "first_process_epoch": source_event_time,
        "tunnel_process_execution_count": (
            1 if validated_endpoint_alert_evidence else 0
        ),
        "reverse_socks_execution_count": (
            1 if reverse_socks_reported else 0
        ),
        "repeated_tunnel_execution_observed": (
            validated_d18_alert_evidence
            and source_reconnect_count > 1
        ),
        "tunnel_process_ids": (
            [source_process_id]
            if validated_endpoint_alert_evidence
            else []
        ),
        "tunnel_process_paths": (
            [source_process_path]
            if validated_endpoint_alert_evidence
            else []
        ),
        "candidate_process_identity_status": (
            "SOURCE_ALERT_IDENTITY_REQUIRES_LIVE_REVALIDATION"
            if validated_endpoint_alert_evidence
            else "NO_CANDIDATE"
        ),
        "event_record_ids": [],
    }

use_source_network_fallback = (
    validated_d18_alert_evidence
    and (
        not network
        or (
            to_int(
                network.get(
                    "total_network_records"
                )
            )
            == 0
            and not to_bool(
                network.get(
                    "c2_channel_supported"
                )
            )
        )
    )
)

if not network or use_source_network_fallback:
    network = {
        "runtime_case_id": validation.get("case_id", ""),
        "runtime_campaign_id": validation.get("campaign_id", ""),
        "runtime_host": validation.get("endpoint_host", ""),
        "runtime_endpoint_address": validation.get("endpoint_address", ""),
        "runtime_callback": source_callback_address,
        "runtime_callback_port": source_callback_port,
        "network_evidence_status": (
            "VALIDATED_D18_CORRELATED_CALLBACK_REPORTED"
            if validated_d18_alert_evidence
            else "NO_MATCHING_NETWORK_EVIDENCE"
        ),
        "c2_channel_supported": validated_d18_alert_evidence,
        "repeated_c2_establishment_observed": (
            validated_d18_alert_evidence
            and source_reconnect_count > 1
        ),
        "network_correlation_strength": (
            "SOURCE_ALERT_CORRELATED"
            if validated_d18_alert_evidence
            else "NONE"
        ),
        "pf_state_evidence_status": (
            "NO_HISTORICAL_FLOW_LIVE_PF_STATE_REVALIDATION_REQUIRED"
        ),
        "evidence_row_found": 0,
        "total_network_records": (
            1 if validated_d18_alert_evidence else 0
        ),
        "earliest_flow_start_epoch": source_first_seen,
        "observed_callback_addresses": (
            [source_callback_address]
            if validated_d18_alert_evidence
            else []
        ),
        "observed_callback_ports": (
            [source_callback_port]
            if validated_d18_alert_evidence
            else []
        ),
        "long_lived_bidirectional_flow_count": (
            1 if validated_d18_alert_evidence else 0
        ),
        "flow_ids": [],
        "suricata_flow_count": 0,
        "filterlog_record_count": 0,
        "distinct_flow_ids": 0,
    }


errors = []

if not to_bool(
    validation.get(
        "alert_validation_valid"
    )
):
    errors.append(
        "ALERT_VALIDATION_INVALID"
    )

required_http_rows = [
    (
        "AUTHORIZATION_SCOPE",
        authorization_status_code,
        authorization,
    ),
    (
        "ENDPOINT_ASSET",
        asset_status_code,
        asset,
    ),
    (
        "PERSISTENCE_EVIDENCE",
        persistence_status_code,
        persistence,
    ),
    (
        "PROCESS_EVIDENCE",
        process_status_code,
        process,
    ),
    (
        "NETWORK_EVIDENCE",
        network_status_code,
        network,
    ),
]

for name, status_code, row in required_http_rows:
    if status_code != 200:
        errors.append(
            name + "_HTTP_STATUS_NOT_200"
        )

    if not row:
        errors.append(
            name + "_RESULT_MISSING"
        )


case_id = text(
    validation.get("case_id")
)

campaign_id = text(
    validation.get("campaign_id")
)

detection_id = text(
    validation.get("detection_id")
).upper()

endpoint_host = text(
    validation.get("endpoint_host")
).upper()

affected_user = text(
    validation.get("affected_user")
).lower()


for source_name, row in (
    ("AUTHORIZATION", authorization),
    ("ASSET", asset),
    ("PERSISTENCE", persistence),
    ("PROCESS", process),
    ("NETWORK", network),
):
    row_case_id = text(
        row.get("runtime_case_id")
    )

    row_campaign_id = text(
        row.get("runtime_campaign_id")
    )

    if (
        row_case_id
        and row_case_id != case_id
    ):
        errors.append(
            source_name
            + "_CASE_ID_MISMATCH"
        )

    if (
        row_campaign_id
        and row_campaign_id
        != campaign_id
    ):
        errors.append(
            source_name
            + "_CAMPAIGN_ID_MISMATCH"
        )


existing_case_found = to_bool(
    existing_lookup.get(
        "found",
        False,
    )
)

existing_value = decode_json(
    existing_lookup.get(
        "value",
        {},
    )
)

if not isinstance(
    existing_value,
    dict,
):
    existing_value = {}

existing_case_record = existing_value.get(
    "case_record",
    existing_value,
)

if not isinstance(
    existing_case_record,
    dict,
):
    existing_case_record = {}

if existing_case_found:
    existing_campaign_id = text(
        existing_case_record.get(
            "campaign_id",
            existing_case_record.get(
                "case_lookup_key",
                "",
            ),
        )
    )

    if (
        existing_campaign_id
        and existing_campaign_id
        != campaign_id
    ):
        errors.append(
            "EXISTING_CASE_CAMPAIGN_MISMATCH"
        )


persistence_supported = to_bool(
    persistence.get(
        "persistence_execution_supported"
    )
)

full_process_chain = (
    text(
        process.get(
            "process_evidence_status"
        )
    ).upper()
    == (
        "FULL_PERSISTENCE_TO_TUNNEL_"
        "PROCESS_CHAIN_FOUND"
    )
)

tunnel_execution_supported = (
    to_int(
        process.get(
            "tunnel_process_execution_count"
        )
    )
    > 0
)

reverse_socks_supported = (
    to_int(
        process.get(
            "reverse_socks_execution_count"
        )
    )
    > 0
)

c2_channel_supported = to_bool(
    network.get(
        "c2_channel_supported"
    )
)

repeated_tunnel_execution = to_bool(
    process.get(
        "repeated_tunnel_execution_observed"
    )
)

repeated_c2_establishment = to_bool(
    network.get(
        "repeated_c2_establishment_observed"
    )
)


correlation_indicators = []

if persistence_supported:
    correlation_indicators.append(
        "PERSISTENCE_EXECUTION_SUPPORTED"
    )

if full_process_chain:
    correlation_indicators.append(
        "EXPLORER_POWERSHELL_CHISEL_CHAIN"
    )

if tunnel_execution_supported:
    correlation_indicators.append(
        "TUNNEL_PROCESS_EXECUTION_SUPPORTED"
    )

if reverse_socks_supported:
    correlation_indicators.append(
        "REVERSE_SOCKS_COMMAND_SUPPORTED"
    )

if c2_channel_supported:
    correlation_indicators.append(
        "LONG_LIVED_BIDIRECTIONAL_C2_SUPPORTED"
    )

if repeated_tunnel_execution:
    correlation_indicators.append(
        "REPEATED_TUNNEL_EXECUTION_OBSERVED"
    )

if repeated_c2_establishment:
    correlation_indicators.append(
        "REPEATED_C2_ESTABLISHMENT_OBSERVED"
    )


signal_count = sum([
    1 if persistence_supported else 0,
    1 if tunnel_execution_supported else 0,
    1 if c2_channel_supported else 0,
])

if (
    persistence_supported
    and tunnel_execution_supported
    and c2_channel_supported
):
    evidence_correlation_strength = "STRONG"
elif signal_count >= 2:
    evidence_correlation_strength = "MODERATE"
elif signal_count == 1:
    evidence_correlation_strength = "LIMITED"
else:
    evidence_correlation_strength = "NONE"


if (
    persistence_supported
    and tunnel_execution_supported
    and c2_channel_supported
):
    evidence_completeness = (
        "COMPLETE_ENDPOINT_AND_NETWORK"
    )
elif (
    persistence_supported
    or tunnel_execution_supported
) and c2_channel_supported:
    evidence_completeness = (
        "PARTIAL_ENDPOINT_AND_NETWORK"
    )
elif (
    persistence_supported
    or tunnel_execution_supported
):
    evidence_completeness = (
        "ENDPOINT_ONLY"
    )
elif c2_channel_supported:
    evidence_completeness = (
        "NETWORK_ONLY"
    )
else:
    evidence_completeness = "NO_CORROBORATION"


timeline = []


def add_timeline_entry(
    event_time,
    order,
    event_type,
    source,
    summary,
    references,
    details,
):
    timeline.append({
        "event_time": text(event_time),
        "order_hint": order,
        "event_type": event_type,
        "source": source,
        "summary": summary,
        "references": ensure_list(
            references
        ),
        "details": details,
    })


add_timeline_entry(
    validation.get(
        "first_seen",
        validation.get(
            "event_time",
            validation.get("last_seen"),
        ),
    ),
    10,
    "DETECTION_ALERT",
    detection_id,
    text(
        validation.get(
            "detection_reason",
            validation.get(
                "attack_stage_hypothesis",
                "",
            ),
        )
    ),
    validation.get(
        "evidence_references",
        [],
    ),
    {
        "search_name": validation.get(
            "search_name",
            "",
        ),
        "detection_key": validation.get(
            "detection_key",
            "",
        ),
        "initial_attack_stage": (
            validation.get(
                "initial_attack_stage",
                "",
            )
        ),
    },
)


if to_int(
    persistence.get(
        "total_persistence_events"
    )
) > 0:
    add_timeline_entry(
        persistence.get(
            "first_persistence_epoch"
        ),
        20,
        "PERSISTENCE_EVIDENCE",
        "SPLUNK_WINDOWS",
        persistence.get(
            "persistence_evidence_status",
            "",
        ),
        persistence.get(
            "event_record_ids",
            [],
        ),
        {
            "signals": persistence.get(
                "persistence_signals",
                [],
            ),
            "powershell_4104_count": (
                persistence.get(
                    "powershell_4104_count",
                    0,
                )
            ),
            "direct_registry_status": (
                persistence.get(
                    "direct_registry_telemetry_status",
                    "",
                )
            ),
        },
    )


if to_int(
    process.get(
        "total_process_powershell_events"
    )
) > 0:
    add_timeline_entry(
        process.get(
            "first_process_epoch"
        ),
        30,
        "PROCESS_EXECUTION",
        "WINDOWS_SECURITY_AND_POWERSHELL",
        process.get(
            "process_evidence_status",
            "",
        ),
        process.get(
            "event_record_ids",
            [],
        ),
        {
            "tunnel_process_ids": (
                process.get(
                    "tunnel_process_ids",
                    [],
                )
            ),
            "tunnel_process_paths": (
                process.get(
                    "tunnel_process_paths",
                    [],
                )
            ),
            "process_identity_status": (
                process.get(
                    "candidate_process_identity_status",
                    "",
                )
            ),
        },
    )


if to_int(
    network.get(
        "total_network_records"
    )
) > 0:
    add_timeline_entry(
        network.get(
            "earliest_flow_start_epoch"
        ),
        40,
        "NETWORK_C2",
        "OPNSENSE_AND_SURICATA",
        network.get(
            "network_evidence_status",
            "",
        ),
        network.get(
            "flow_ids",
            [],
        ),
        {
            "callback_addresses": (
                network.get(
                    "observed_callback_addresses",
                    [],
                )
            ),
            "callback_ports": (
                network.get(
                    "observed_callback_ports",
                    [],
                )
            ),
            "long_lived_flow_count": (
                network.get(
                    "long_lived_bidirectional_flow_count",
                    0,
                )
            ),
            "network_strength": (
                network.get(
                    "network_correlation_strength",
                    "NONE",
                )
            ),
        },
    )


add_timeline_entry(
    authorization.get(
        "evaluation_time"
    ),
    50,
    "AUTHORIZATION_EVALUATION",
    "PB05_AUTHORIZATION_LOOKUP",
    authorization.get(
        "authorization_status",
        "NOT_AUTHORIZED",
    ),
    [],
    {
        "scope_reason": authorization.get(
            "scope_reason",
            "",
        ),
        "exercise_name": authorization.get(
            "exercise_name",
            "",
        ),
        "owner": authorization.get(
            "owner",
            "",
        ),
    },
)


def timeline_sort_key(entry):
    parsed = parse_time(
        entry.get("event_time")
    )

    if parsed is None:
        parsed = datetime.max.replace(
            tzinfo=timezone.utc
        )

    return (
        parsed,
        entry.get(
            "order_hint",
            999,
        ),
    )


timeline.sort(
    key=timeline_sort_key
)

for index, entry in enumerate(
    timeline,
    start=1,
):
    entry["sequence"] = index
    entry.pop(
        "order_hint",
        None,
    )


telemetry_gaps = []

if (
    text(
        persistence.get(
            "direct_registry_telemetry_status"
        )
    ).upper()
    != "DIRECT_REGISTRY_TELEMETRY_FOUND"
):
    telemetry_gaps.append(
        "DIRECT_REGISTRY_CHANGE_TELEMETRY_NOT_OBSERVED"
    )

telemetry_gaps.extend([
    "LIVE_PROCESS_STATE_NOT_YET_REVALIDATED",
    "LIVE_USER_SID_AND_HIVE_NOT_YET_REVALIDATED",
    "LIVE_PF_STATE_NOT_YET_REVALIDATED",
])


timeline_build_valid = (
    len(errors) == 0
)

built_at = (
    datetime.now(timezone.utc)
    .isoformat()
    .replace("+00:00", "Z")
)

output = {
    "schema_version": "PB05_TIMELINE_V1",
    "playbook_id": "PB05",

    "timeline_build_valid": (
        timeline_build_valid
    ),
    "timeline_build_status": (
        "PB05_TIMELINE_BUILT"
        if timeline_build_valid
        else "FAILED_CLOSED"
    ),
    "timeline_build_errors": errors,

    "case_id": case_id,
    "campaign_id": campaign_id,
    "case_lookup_key": campaign_id,

    "detection_id": detection_id,
    "search_name": validation.get(
        "search_name",
        "",
    ),
    "initial_attack_stage": validation.get(
        "initial_attack_stage",
        "",
    ),
    "attack_stage_hypothesis": validation.get(
        "attack_stage_hypothesis",
        "",
    ),
    "final_attack_stage": "NOT_ASSESSED",

    "endpoint_host": endpoint_host,
    "endpoint_address": validation.get(
        "endpoint_address",
        "",
    ),
    "affected_user": affected_user,
    "affected_domain": validation.get(
        "affected_domain",
        "",
    ),
    "user_sid": validation.get(
        "user_sid",
        "",
    ),

    "authorization_status": authorization.get(
        "authorization_status",
        "NOT_AUTHORIZED",
    ),
    "authorized_test": to_bool(
        authorization.get(
            "authorized_test"
        )
    ),
    "authorization_scope_reason": (
        authorization.get(
            "scope_reason",
            "",
        )
    ),

    "existing_case_found": (
        existing_case_found
    ),
    "existing_case_record": (
        existing_case_record
        if existing_case_found
        else {}
    ),

    "endpoint_asset": asset,
    "persistence_evidence": persistence,
    "process_evidence": process,
    "network_evidence": network,

    "persistence_execution_supported": (
        persistence_supported
    ),
    "full_process_chain_supported": (
        full_process_chain
    ),
    "tunnel_execution_supported": (
        tunnel_execution_supported
    ),
    "reverse_socks_supported": (
        reverse_socks_supported
    ),
    "c2_channel_supported": (
        c2_channel_supported
    ),
    "repeated_tunnel_execution_observed": (
        repeated_tunnel_execution
    ),
    "repeated_c2_establishment_observed": (
        repeated_c2_establishment
    ),
    "advanced_post_exploitation_observed": False,

    "correlation_indicators": (
        correlation_indicators
    ),
    "evidence_correlation_strength": (
        evidence_correlation_strength
    ),
    "evidence_completeness": (
        evidence_completeness
    ),
    "evidence_timeline": timeline,
    "telemetry_gaps": telemetry_gaps,

    "entity_consistency_status": (
        "CONSISTENT_WITH_ENDPOINT_ASSET_LOOKUP"
        if to_bool(
            asset.get("endpoint_known")
        )
        else "ENDPOINT_ASSET_UNCONFIRMED"
    ),

    "assessment_status": (
        "READY_FOR_STAGE_ASSESSMENT"
        if timeline_build_valid
        else "ASSESSMENT_BLOCKED"
    ),
    "investigation_phase": (
        "TIMELINE_BUILT"
        if timeline_build_valid
        else "TIMELINE_FAILED"
    ),

    "fail_closed": (
        not timeline_build_valid
    ),
    "automated_response_allowed": False,
    "timeline_built_at": built_at,
}

print(
    json.dumps(
        output,
        default=str,
    )
)
