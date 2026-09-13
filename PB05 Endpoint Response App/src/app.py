import base64
import gzip
import ipaddress
import json
import re
from datetime import datetime

import winrm
from shuffle_sdk import AppBase


class PB05EndpointResponse(AppBase):
    __version__ = "1.0.0"
    app_name = "PB05 Endpoint Response"

    ALLOWED_ENDPOINT_ADDRESS = "10.10.30.20"
    ALLOWED_ENDPOINT_HOST = "WIN10-CLIENT01"
    ALLOWED_DOMAIN = "LAB"
    ALLOWED_LOGIN_USER = "svc_soar_pb05"
    ALLOWED_AFFECTED_USER = "svc_web"
    ALLOWED_USER_SID = "S-1-5-21-722403993-16450863-2166090910-1106"
    ALLOWED_PROCESS_NAME = "chisel.exe"
    ALLOWED_RUN_VALUE_NAME = "PFA-Lab-Tunnel"
    ALLOWED_CALLBACK_ADDRESS = "192.168.111.144"
    ALLOWED_CALLBACK_PORT = 443
    ALLOWED_WINRM_PORT = 5985

    CASE_ID_PATTERN = re.compile(r"^PB05-CASE-[A-F0-9]{16}$")

    @staticmethod
    def _json(payload):
        return json.dumps(payload, separators=(",", ":"), default=str)

    @staticmethod
    def _text(value):
        return "" if value is None else str(value).strip()

    @staticmethod
    def _ps_literal(value):
        value = "" if value is None else str(value)
        if "\x00" in value or len(value) > 8192:
            raise ValueError("Unsafe or oversized PowerShell literal")
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _short_host(value):
        return str(value or "").strip().split(".", 1)[0].upper()

    @staticmethod
    def _short_user(value):
        value = str(value or "").strip()
        return re.split(r"[\\@]", value)[-1].lower()

    def _validate_connection(self, server, port, domain, login_user):
        errors = []
        server_text = self._text(server)
        try:
            server_ip = str(ipaddress.ip_address(server_text))
        except ValueError:
            server_ip = ""
            errors.append("INVALID_SERVER_ADDRESS")

        if server_ip != self.ALLOWED_ENDPOINT_ADDRESS:
            errors.append("SERVER_NOT_ALLOWLISTED")

        try:
            port_number = int(str(port).strip())
        except (TypeError, ValueError):
            port_number = 0
        if port_number != self.ALLOWED_WINRM_PORT:
            errors.append("WINRM_PORT_NOT_ALLOWLISTED")

        if self._text(domain).upper() != self.ALLOWED_DOMAIN:
            errors.append("DOMAIN_NOT_ALLOWLISTED")
        if self._text(login_user).lower() != self.ALLOWED_LOGIN_USER:
            errors.append("MANAGEMENT_IDENTITY_NOT_ALLOWLISTED")

        return errors

    def _validate_case_and_host(self, case_id, target_host):
        errors = []
        normalized_case_id = self._text(case_id).upper()
        if not self.CASE_ID_PATTERN.fullmatch(normalized_case_id):
            errors.append("INVALID_CASE_ID")
        if self._short_host(target_host) != self.ALLOWED_ENDPOINT_HOST:
            errors.append("TARGET_HOST_NOT_ALLOWLISTED")
        return errors, normalized_case_id

    def _validate_common_scope(
        self,
        case_id,
        target_host,
        target_user_sid=None,
        process_name=None,
        run_value_name=None,
        callback_address=None,
        callback_port=None,
    ):
        errors, normalized_case_id = self._validate_case_and_host(case_id, target_host)

        if target_user_sid is not None and self._text(target_user_sid) != self.ALLOWED_USER_SID:
            errors.append("TARGET_USER_SID_NOT_ALLOWLISTED")
        if process_name is not None and self._text(process_name).lower() != self.ALLOWED_PROCESS_NAME:
            errors.append("PROCESS_NAME_NOT_ALLOWLISTED")
        if run_value_name is not None and self._text(run_value_name) != self.ALLOWED_RUN_VALUE_NAME:
            errors.append("RUN_VALUE_NAME_NOT_ALLOWLISTED")

        if callback_address is not None:
            try:
                normalized_address = str(ipaddress.ip_address(self._text(callback_address)))
            except ValueError:
                normalized_address = ""
                errors.append("INVALID_CALLBACK_ADDRESS")
            if normalized_address != self.ALLOWED_CALLBACK_ADDRESS:
                errors.append("CALLBACK_ADDRESS_NOT_ALLOWLISTED")

        if callback_port is not None:
            try:
                normalized_port = int(str(callback_port).strip())
            except (TypeError, ValueError):
                normalized_port = 0
                errors.append("INVALID_CALLBACK_PORT")
            if normalized_port != self.ALLOWED_CALLBACK_PORT:
                errors.append("CALLBACK_PORT_NOT_ALLOWLISTED")

        return errors, normalized_case_id

    def _session(self, server, port, domain, login_user, password):
        endpoint = "http://{}:{}/wsman".format(self._text(server), int(port))
        username = "{}\\{}".format(self._text(domain), self._text(login_user))
        return winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            message_encryption="always",
            server_cert_validation="ignore",
            read_timeout_sec=60,
            operation_timeout_sec=30,
            proxy=None,
        )

    def _execute_ps(self, server, port, domain, login_user, password, script):
        compressed_script = base64.b64encode(
            gzip.compress(script.encode("utf-8"), compresslevel=9)
        ).decode("ascii")
        launcher = (
            "$d=[Convert]::FromBase64String('{}');"
            "$m=[IO.MemoryStream]::new($d);"
            "$g=[IO.Compression.GzipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
            "$r=[IO.StreamReader]::new($g,[Text.Encoding]::UTF8);"
            "iex ($r.ReadToEnd())"
        ).format(compressed_script)

        try:
            result = self._session(server, port, domain, login_user, password).run_ps(launcher)
        except Exception as exc:
            return {
                "success": False,
                "execution_status": "WINRM_CONNECTION_FAILED",
                "error": "{}: {}".format(type(exc).__name__, str(exc))[:2000],
            }

        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        if result.status_code != 0:
            return {
                "success": False,
                "execution_status": "POWERSHELL_FAILED",
                "status_code": result.status_code,
                "stderr": stderr[:4000],
            }

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return {
                "success": False,
                "execution_status": "INVALID_ENDPOINT_RESPONSE",
                "status_code": result.status_code,
                "stdout": stdout[:4000],
                "stderr": stderr[:4000],
            }

        if not isinstance(payload, dict):
            return {
                "success": False,
                "execution_status": "INVALID_ENDPOINT_RESPONSE_TYPE",
            }
        return payload

    def _scope_failure(self, case_id, errors):
        return self._json(
            {
                "success": False,
                "case_id": self._text(case_id).upper(),
                "scope_validation_status": "FAILED_CLOSED",
                "errors": sorted(set(errors)),
            }
        )

    def get_pb05_endpoint_state(
        self,
        server,
        port,
        domain,
        login_user,
        password,
        case_id,
        target_host,
        target_user_sid,
        process_name,
        run_value_name,
        callback_address,
        callback_port,
    ):
        errors = self._validate_connection(server, port, domain, login_user)
        scope_errors, normalized_case_id = self._validate_common_scope(
            case_id,
            target_host,
            target_user_sid=target_user_sid,
            process_name=process_name,
            run_value_name=run_value_name,
            callback_address=callback_address,
            callback_port=callback_port,
        )
        errors.extend(scope_errors)
        if errors:
            return self._scope_failure(case_id, errors)

        replacements = {
            "__CASE_ID__": self._ps_literal(normalized_case_id),
            "__HOST__": self._ps_literal(self.ALLOWED_ENDPOINT_HOST),
            "__SID__": self._ps_literal(self.ALLOWED_USER_SID),
            "__PROCESS__": self._ps_literal(self.ALLOWED_PROCESS_NAME),
            "__RUN_VALUE__": self._ps_literal(self.ALLOWED_RUN_VALUE_NAME),
            "__CALLBACK__": self._ps_literal(self.ALLOWED_CALLBACK_ADDRESS),
            "__CALLBACK_PORT__": str(self.ALLOWED_CALLBACK_PORT),
            "__AFFECTED_USER__": self._ps_literal(self.ALLOWED_AFFECTED_USER),
        }
        script = r"""
$ErrorActionPreference = 'Stop'
$CaseId = __CASE_ID__
$ExpectedHost = __HOST__
$UserSid = __SID__
$ProcessName = __PROCESS__
$RunValueName = __RUN_VALUE__
$CallbackAddress = __CALLBACK__
$CallbackPort = __CALLBACK_PORT__
$AffectedUser = __AFFECTED_USER__

if ($env:COMPUTERNAME -ine $ExpectedHost) {
    throw "TARGET_HOST_MISMATCH"
}

function Convert-CreationTimeToIso([object]$Value) {
    if ($null -eq $Value) { return "" }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    try {
        return ([Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)).ToUniversalTime().ToString('o')
    } catch { return [string]$Value }
}

function Resolve-ProcessPath([object]$Process) {
    $Path = ([string]$Process.ExecutablePath).Trim()
    if ($Path) { return $Path }

    # Win32_Process.ExecutablePath can be blank when the WinRM identity does
    # not hold SeDebugPrivilege. Recover only the leading executable token;
    # the stop action still verifies PID, creation time, owner, full command
    # line and callback before changing endpoint state.
    $Command = ([string]$Process.CommandLine).Trim()
    if ($Command -match '^\s*"([^\"]+\.exe)"') { return $Matches[1] }
    if ($Command -match '^\s*([^\s\"]+\.exe)(?:\s|$)') { return $Matches[1] }
    return ""
}

$RunPath = "Registry::HKEY_USERS\$UserSid\Software\Microsoft\Windows\CurrentVersion\Run"
$HiveLoaded = Test-Path -LiteralPath "Registry::HKEY_USERS\$UserSid"
$RunPathPresent = Test-Path -LiteralPath $RunPath
$RunValuePresent = $false
$RunValueData = ""
if ($RunPathPresent) {
    $RunItem = Get-ItemProperty -LiteralPath $RunPath -ErrorAction Stop
    $RunProperty = $RunItem.PSObject.Properties[$RunValueName]
    if ($null -ne $RunProperty) {
        $RunValuePresent = $true
        $RunValueData = [string]$RunProperty.Value
    }
}

$CallbackNeedle = "$CallbackAddress`:$CallbackPort"
$Processes = @()
foreach ($Process in @(Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq $ProcessName })) {
    $Owner = ""
    try {
        $OwnerResult = Invoke-CimMethod -InputObject $Process -MethodName GetOwner -ErrorAction Stop
        if ($OwnerResult.ReturnValue -eq 0) {
            $Owner = "$($OwnerResult.Domain)\$($OwnerResult.User)"
        }
    } catch {}

    $CommandLine = ([string]$Process.CommandLine).Trim()
    $ExecutablePath = Resolve-ProcessPath $Process
    $Hash = ""
    if ($ExecutablePath -and (Test-Path -LiteralPath $ExecutablePath)) {
        try { $Hash = (Get-FileHash -LiteralPath $ExecutablePath -Algorithm SHA256).Hash } catch {}
    }
    $OwnerShort = ($Owner -split '\\')[-1]
    $Processes += [ordered]@{
        process_id = [int]$Process.ProcessId
        parent_process_id = [int]$Process.ParentProcessId
        process_name = [string]$Process.Name
        process_path = $ExecutablePath
        command_line = $CommandLine
        creation_time = Convert-CreationTimeToIso $Process.CreationDate
        process_user = $Owner
        user_match = ($OwnerShort -ieq $AffectedUser)
        callback_match = ($CommandLine.IndexOf($CallbackNeedle, [StringComparison]::OrdinalIgnoreCase) -ge 0)
        sha256 = $Hash
    }
}

$MatchingProcesses = @($Processes | Where-Object { $_.user_match -and $_.callback_match })
[ordered]@{
    success = $true
    schema_version = 'PB05_ENDPOINT_STATE_V1'
    case_id = $CaseId
    target_host = $env:COMPUTERNAME
    target_user_sid = $UserSid
    user_hive_loaded = $HiveLoaded
    persistence = [ordered]@{
        registry_path = $RunPath
        value_name = $RunValueName
        present = $RunValuePresent
        value_data = $RunValueData
    }
    process_name = $ProcessName
    processes = @($Processes)
    matching_processes = @($MatchingProcesses)
    matching_process_count = @($MatchingProcesses).Count
    callback_address = $CallbackAddress
    callback_port = $CallbackPort
    state_capture_status = 'CAPTURED'
    captured_at = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 10 -Compress
"""
        for marker, replacement in replacements.items():
            script = script.replace(marker, replacement)

        return self._json(
            self._execute_ps(server, port, domain, login_user, password, script)
        )

    def stop_verified_process(
        self,
        server,
        port,
        domain,
        login_user,
        password,
        case_id,
        target_host,
        process_id,
        expected_process_name,
        expected_process_path,
        expected_command_line,
        expected_process_creation_time,
        expected_process_user,
        callback_address,
        callback_port,
    ):
        errors = self._validate_connection(server, port, domain, login_user)
        scope_errors, normalized_case_id = self._validate_common_scope(
            case_id,
            target_host,
            process_name=expected_process_name,
            callback_address=callback_address,
            callback_port=callback_port,
        )
        errors.extend(scope_errors)

        try:
            normalized_pid = int(str(process_id).strip())
            if normalized_pid <= 0 or normalized_pid > 4194304:
                raise ValueError
        except (TypeError, ValueError):
            normalized_pid = 0
            errors.append("INVALID_PROCESS_ID")

        expected_path = self._text(expected_process_path)
        expected_cmd = self._text(expected_command_line)
        expected_created = self._text(expected_process_creation_time)
        expected_user = self._text(expected_process_user)

        if not expected_path or len(expected_path) > 1024 or not expected_path.lower().endswith("\\chisel.exe"):
            errors.append("INVALID_EXPECTED_PROCESS_PATH")
        callback_needle = "{}:{}".format(
            self.ALLOWED_CALLBACK_ADDRESS, self.ALLOWED_CALLBACK_PORT
        )
        if not expected_cmd or len(expected_cmd) > 8192 or callback_needle.lower() not in expected_cmd.lower():
            errors.append("INVALID_EXPECTED_COMMAND_LINE")
        try:
            # PowerShell's round-trip ("o") format emits seven fractional
            # second digits. Python 3.10 accepts at most six, so trim only
            # the validation copy and preserve the original value for the
            # exact live-state comparison performed on the endpoint.
            creation_time_for_validation = re.sub(
                r"(\.\d{6})\d+(?=(?:Z|[+-]\d{2}:\d{2})?$)",
                r"\1",
                expected_created,
            )
            datetime.fromisoformat(
                creation_time_for_validation.replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            errors.append("INVALID_EXPECTED_CREATION_TIME")
        if self._short_user(expected_user) != self.ALLOWED_AFFECTED_USER:
            errors.append("PROCESS_USER_NOT_ALLOWLISTED")

        if errors:
            return self._scope_failure(case_id, errors)

        replacements = {
            "__CASE_ID__": self._ps_literal(normalized_case_id),
            "__HOST__": self._ps_literal(self.ALLOWED_ENDPOINT_HOST),
            "__PID__": str(normalized_pid),
            "__PROCESS__": self._ps_literal(self.ALLOWED_PROCESS_NAME),
            "__PATH__": self._ps_literal(expected_path),
            "__COMMAND__": self._ps_literal(expected_cmd),
            "__CREATED__": self._ps_literal(expected_created),
            "__USER__": self._ps_literal(expected_user),
            "__CALLBACK__": self._ps_literal(callback_needle),
        }
        script = r"""
$ErrorActionPreference = 'Stop'
$CaseId = __CASE_ID__
$ExpectedHost = __HOST__
$ExpectedPid = __PID__
$ExpectedName = __PROCESS__
$ExpectedPath = __PATH__
$ExpectedCommand = __COMMAND__
$ExpectedCreated = __CREATED__
$ExpectedUser = __USER__
$CallbackNeedle = __CALLBACK__

if ($env:COMPUTERNAME -ine $ExpectedHost) { throw "TARGET_HOST_MISMATCH" }

function Convert-CreationTimeToIso([object]$Value) {
    if ($null -eq $Value) { return "" }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    try {
        return ([Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)).ToUniversalTime().ToString('o')
    } catch { return [string]$Value }
}

function Resolve-ProcessPath([object]$Process) {
    $Path = ([string]$Process.ExecutablePath).Trim()
    if ($Path) { return $Path }

    $Command = ([string]$Process.CommandLine).Trim()
    if ($Command -match '^\s*"([^\"]+\.exe)"') { return $Matches[1] }
    if ($Command -match '^\s*([^\s\"]+\.exe)(?:\s|$)') { return $Matches[1] }
    return ""
}

$Process = Get-CimInstance Win32_Process -Filter "ProcessId=$ExpectedPid" -ErrorAction SilentlyContinue
if ($null -eq $Process) {
    [ordered]@{
        success = $true
        schema_version = 'PB05_PROCESS_STOP_V1'
        case_id = $CaseId
        process_id = $ExpectedPid
        process_stop_status = 'ALREADY_ABSENT'
        stopped = $false
        verified_absent = $true
    } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}

$Owner = ""
try {
    $OwnerResult = Invoke-CimMethod -InputObject $Process -MethodName GetOwner -ErrorAction Stop
    if ($OwnerResult.ReturnValue -eq 0) { $Owner = "$($OwnerResult.Domain)\$($OwnerResult.User)" }
} catch {}

$ActualCreated = Convert-CreationTimeToIso $Process.CreationDate
$ActualPath = Resolve-ProcessPath $Process
$ActualCommand = ([string]$Process.CommandLine).Trim()
$ExpectedPathNormalized = ([string]$ExpectedPath).Trim()
$ExpectedCommandNormalized = ([string]$ExpectedCommand).Trim()
$OwnerShort = ($Owner -split '\\')[-1]
$ExpectedUserShort = ($ExpectedUser -split '\\')[-1]
$Mismatches = @()
if ([string]$Process.Name -ine $ExpectedName) { $Mismatches += 'PROCESS_NAME_CHANGED' }
if ($ActualPath -ine $ExpectedPathNormalized) { $Mismatches += 'PROCESS_PATH_CHANGED' }
if ($ActualCommand -cne $ExpectedCommandNormalized) { $Mismatches += 'COMMAND_LINE_CHANGED' }
if ($ActualCreated -ne $ExpectedCreated) { $Mismatches += 'PROCESS_CREATION_TIME_CHANGED' }
if ($OwnerShort -ine $ExpectedUserShort) { $Mismatches += 'PROCESS_USER_CHANGED' }
if ($ActualCommand -notlike "*$CallbackNeedle*") { $Mismatches += 'CALLBACK_CONTEXT_CHANGED' }

if ($Mismatches.Count -gt 0) {
    [ordered]@{
        success = $false
        schema_version = 'PB05_PROCESS_STOP_V1'
        case_id = $CaseId
        process_id = $ExpectedPid
        process_stop_status = 'REFUSED_PROCESS_STATE_CHANGED'
        mismatches = @($Mismatches)
        actual_state = [ordered]@{
            process_name = [string]$Process.Name
            process_path = $ActualPath
            command_line = $ActualCommand
            creation_time = $ActualCreated
            process_user = $Owner
        }
        stopped = $false
        verified_absent = $false
    } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}

Stop-Process -Id $ExpectedPid -Force -ErrorAction Stop
Start-Sleep -Milliseconds 750
$StillPresent = $null -ne (Get-Process -Id $ExpectedPid -ErrorAction SilentlyContinue)
[ordered]@{
    success = (-not $StillPresent)
    schema_version = 'PB05_PROCESS_STOP_V1'
    case_id = $CaseId
    process_id = $ExpectedPid
    process_stop_status = if ($StillPresent) { 'STOP_NOT_VERIFIED' } else { 'STOPPED_AND_VERIFIED' }
    stopped = $true
    verified_absent = (-not $StillPresent)
} | ConvertTo-Json -Depth 8 -Compress
"""
        for marker, replacement in replacements.items():
            script = script.replace(marker, replacement)

        return self._json(
            self._execute_ps(server, port, domain, login_user, password, script)
        )

    def remove_verified_run_value(
        self,
        server,
        port,
        domain,
        login_user,
        password,
        case_id,
        target_host,
        target_user_sid,
        run_value_name,
        expected_value_data,
    ):
        errors = self._validate_connection(server, port, domain, login_user)
        scope_errors, normalized_case_id = self._validate_common_scope(
            case_id,
            target_host,
            target_user_sid=target_user_sid,
            run_value_name=run_value_name,
        )
        errors.extend(scope_errors)
        expected_data = "" if expected_value_data is None else str(expected_value_data)
        if not expected_data or len(expected_data) > 8192:
            errors.append("INVALID_EXPECTED_RUN_VALUE_DATA")
        if errors:
            return self._scope_failure(case_id, errors)

        replacements = {
            "__CASE_ID__": self._ps_literal(normalized_case_id),
            "__HOST__": self._ps_literal(self.ALLOWED_ENDPOINT_HOST),
            "__SID__": self._ps_literal(self.ALLOWED_USER_SID),
            "__RUN_VALUE__": self._ps_literal(self.ALLOWED_RUN_VALUE_NAME),
            "__EXPECTED_DATA__": self._ps_literal(expected_data),
        }
        script = r"""
$ErrorActionPreference = 'Stop'
$CaseId = __CASE_ID__
$ExpectedHost = __HOST__
$UserSid = __SID__
$RunValueName = __RUN_VALUE__
$ExpectedData = __EXPECTED_DATA__

if ($env:COMPUTERNAME -ine $ExpectedHost) { throw "TARGET_HOST_MISMATCH" }

$HivePath = "Registry::HKEY_USERS\$UserSid"
$RunPath = "$HivePath\Software\Microsoft\Windows\CurrentVersion\Run"
if (-not (Test-Path -LiteralPath $HivePath)) { throw "TARGET_USER_HIVE_NOT_LOADED" }
if (-not (Test-Path -LiteralPath $RunPath)) {
    [ordered]@{
        success = $true
        schema_version = 'PB05_RUN_VALUE_REMOVAL_V1'
        case_id = $CaseId
        registry_path = $RunPath
        value_name = $RunValueName
        persistence_removal_status = 'ALREADY_ABSENT'
        removed = $false
        verified_absent = $true
    } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}

$RunItem = Get-ItemProperty -LiteralPath $RunPath -ErrorAction Stop
$RunProperty = $RunItem.PSObject.Properties[$RunValueName]
if ($null -eq $RunProperty) {
    [ordered]@{
        success = $true
        schema_version = 'PB05_RUN_VALUE_REMOVAL_V1'
        case_id = $CaseId
        registry_path = $RunPath
        value_name = $RunValueName
        persistence_removal_status = 'ALREADY_ABSENT'
        removed = $false
        verified_absent = $true
    } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}

$ActualData = [string]$RunProperty.Value
if ($ActualData -cne $ExpectedData) {
    [ordered]@{
        success = $false
        schema_version = 'PB05_RUN_VALUE_REMOVAL_V1'
        case_id = $CaseId
        registry_path = $RunPath
        value_name = $RunValueName
        persistence_removal_status = 'REFUSED_VALUE_DATA_CHANGED'
        removed = $false
        verified_absent = $false
    } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}

Remove-ItemProperty -LiteralPath $RunPath -Name $RunValueName -ErrorAction Stop
$AfterItem = Get-ItemProperty -LiteralPath $RunPath -ErrorAction Stop
$StillPresent = $null -ne $AfterItem.PSObject.Properties[$RunValueName]
[ordered]@{
    success = (-not $StillPresent)
    schema_version = 'PB05_RUN_VALUE_REMOVAL_V1'
    case_id = $CaseId
    registry_path = $RunPath
    value_name = $RunValueName
    persistence_removal_status = if ($StillPresent) { 'REMOVAL_NOT_VERIFIED' } else { 'REMOVED_AND_VERIFIED' }
    removed = $true
    verified_absent = (-not $StillPresent)
} | ConvertTo-Json -Depth 8 -Compress
"""
        for marker, replacement in replacements.items():
            script = script.replace(marker, replacement)

        return self._json(
            self._execute_ps(server, port, domain, login_user, password, script)
        )

    def verify_pb05_endpoint_state(
        self,
        server,
        port,
        domain,
        login_user,
        password,
        case_id,
        target_host,
        target_user_sid,
        process_name,
        run_value_name,
        callback_address,
        callback_port,
    ):
        errors = self._validate_connection(server, port, domain, login_user)
        scope_errors, normalized_case_id = self._validate_common_scope(
            case_id,
            target_host,
            target_user_sid=target_user_sid,
            process_name=process_name,
            run_value_name=run_value_name,
            callback_address=callback_address,
            callback_port=callback_port,
        )
        errors.extend(scope_errors)
        if errors:
            return self._scope_failure(case_id, errors)

        replacements = {
            "__CASE_ID__": self._ps_literal(normalized_case_id),
            "__HOST__": self._ps_literal(self.ALLOWED_ENDPOINT_HOST),
            "__SID__": self._ps_literal(self.ALLOWED_USER_SID),
            "__PROCESS__": self._ps_literal(self.ALLOWED_PROCESS_NAME),
            "__RUN_VALUE__": self._ps_literal(self.ALLOWED_RUN_VALUE_NAME),
            "__CALLBACK__": self._ps_literal(self.ALLOWED_CALLBACK_ADDRESS),
            "__CALLBACK_PORT__": str(self.ALLOWED_CALLBACK_PORT),
            "__AFFECTED_USER__": self._ps_literal(self.ALLOWED_AFFECTED_USER),
        }
        script = r"""
$ErrorActionPreference = 'Stop'
$CaseId = __CASE_ID__
$ExpectedHost = __HOST__
$UserSid = __SID__
$ProcessName = __PROCESS__
$RunValueName = __RUN_VALUE__
$CallbackAddress = __CALLBACK__
$CallbackPort = __CALLBACK_PORT__
$AffectedUser = __AFFECTED_USER__

if ($env:COMPUTERNAME -ine $ExpectedHost) { throw "TARGET_HOST_MISMATCH" }

$RunPath = "Registry::HKEY_USERS\$UserSid\Software\Microsoft\Windows\CurrentVersion\Run"
$HiveLoaded = Test-Path -LiteralPath "Registry::HKEY_USERS\$UserSid"
$RunValuePresent = $false
if (Test-Path -LiteralPath $RunPath) {
    $RunItem = Get-ItemProperty -LiteralPath $RunPath -ErrorAction Stop
    $RunValuePresent = $null -ne $RunItem.PSObject.Properties[$RunValueName]
}

$CallbackNeedle = "$CallbackAddress`:$CallbackPort"
$MatchingProcesses = @()
foreach ($Process in @(Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq $ProcessName })) {
    $Owner = ""
    try {
        $OwnerResult = Invoke-CimMethod -InputObject $Process -MethodName GetOwner -ErrorAction Stop
        if ($OwnerResult.ReturnValue -eq 0) { $Owner = "$($OwnerResult.Domain)\$($OwnerResult.User)" }
    } catch {}
    $OwnerShort = ($Owner -split '\\')[-1]
    $CommandLine = [string]$Process.CommandLine
    if ($OwnerShort -ieq $AffectedUser -and $CommandLine.IndexOf($CallbackNeedle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $MatchingProcesses += [ordered]@{
            process_id = [int]$Process.ProcessId
            process_name = [string]$Process.Name
            process_path = [string]$Process.ExecutablePath
            command_line = $CommandLine
            process_user = $Owner
        }
    }
}

$ProcessAbsent = @($MatchingProcesses).Count -eq 0
$PersistenceAbsent = -not $RunValuePresent
$Verified = $ProcessAbsent -and $PersistenceAbsent
[ordered]@{
    success = $true
    schema_version = 'PB05_ENDPOINT_VERIFICATION_V1'
    case_id = $CaseId
    target_host = $env:COMPUTERNAME
    target_user_sid = $UserSid
    user_hive_loaded = $HiveLoaded
    tunnel_process_absent = $ProcessAbsent
    matching_processes = @($MatchingProcesses)
    process_restart = if ($ProcessAbsent) { 'NOT_OBSERVED' } else { 'OBSERVED' }
    run_value_absent = $PersistenceAbsent
    callback_restart = if ($ProcessAbsent) { 'NOT_OBSERVED_AT_ENDPOINT' } else { 'POSSIBLE' }
    endpoint_containment_status = if ($Verified) { 'VERIFIED' } else { 'FAILED_OR_PARTIAL' }
    verified_at = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 10 -Compress
"""
        for marker, replacement in replacements.items():
            script = script.replace(marker, replacement)

        return self._json(
            self._execute_ps(server, port, domain, login_user, password, script)
        )


if __name__ == "__main__":
    PB05EndpointResponse.run()
