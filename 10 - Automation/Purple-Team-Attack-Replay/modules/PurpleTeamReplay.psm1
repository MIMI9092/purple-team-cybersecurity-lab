Set-StrictMode -Version Latest

$script:ApprovedLabAddresses = @(
    '192.168.111.144',
    '10.10.70.1',
    '10.10.30.10',
    '10.10.30.20',
    '10.10.50.10',
    '10.10.50.30',
    '10.10.60.10',
    '192.168.111.128'
)

function New-ReplayRunContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $RootPath,
        [Parameter(Mandatory)] [string] $Scenario,
        [Parameter(Mandatory)] [string] $Mode
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $runId = "PTR-$timestamp-$suffix"
    $evidencePath = Join-Path $RootPath "evidence\$runId"

    if (-not (Test-Path -LiteralPath $evidencePath)) {
        New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null
    }

    [pscustomobject]@{
        RunId        = $runId
        Scenario     = $Scenario
        Mode         = $Mode
        StartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        EvidencePath = $evidencePath
        EventLogPath = Join-Path $evidencePath 'events.jsonl'
    }
}

function Write-ReplayEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $Level,
        [Parameter(Mandatory)] [string] $Event,
        [Parameter()] $Data = @{}
    )

    $record = [ordered]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        run_id        = $Context.RunId
        scenario      = $Context.Scenario
        mode          = $Context.Mode
        level         = $Level
        event         = $Event
        data          = $Data
    }
    $record | ConvertTo-Json -Depth 8 -Compress |
        Add-Content -LiteralPath $Context.EventLogPath -Encoding UTF8
}

function Assert-ReplayLabScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    $configured = @(
        $Config.Hosts.Kali.Address
        $Config.Hosts.OPNsense.Address
        $Config.Hosts.DomainController.Address
        $Config.Hosts.Windows10.Address
        $Config.Hosts.Splunk.Address
        $Config.Hosts.Shuffle.Address
        $Config.Hosts.Dvwa.Address
        $Config.Hosts.Dvwa.ExternalAddress
        $Config.PB05.CallbackAddress
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) }

    $invalid = @($configured | Where-Object { $_ -notin $script:ApprovedLabAddresses } | Select-Object -Unique)
    if ($invalid.Count -gt 0) {
        throw "Configuration contains addresses outside the project allowlist: $($invalid -join ', ')"
    }

    $duplicateUnexpected = @($configured | Group-Object | Where-Object {
        $_.Count -gt 1 -and $_.Name -ne $Config.Hosts.Kali.Address
    })
    if ($duplicateUnexpected.Count -gt 0) {
        throw "Configuration contains an unexpected duplicate address: $($duplicateUnexpected.Name -join ', ')"
    }

    $true
}

function Test-ReplayTcpPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [int] $TimeoutMilliseconds = 1500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Get-RunningVmPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $VmRunPath)

    if (-not (Test-Path -LiteralPath $VmRunPath -PathType Leaf)) {
        return @()
    }

    $output = & $VmRunPath list 2>&1
    @($output | Select-Object -Skip 1 | ForEach-Object { [string] $_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Start-ReplayVirtualMachines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] $ScenarioDefinition,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $vmRunPath = [string] $Config.Tools.VmRunPath
    if (-not (Test-Path -LiteralPath $vmRunPath -PathType Leaf)) {
        throw "vmrun was not found: $vmRunPath"
    }

    $runningVmPaths = @(Get-RunningVmPaths -VmRunPath $vmRunPath)
    $excludedRunning = New-Object System.Collections.Generic.List[string]
    if ($Config.ContainsKey('AttackOnlyExcludedVirtualMachines')) {
        foreach ($vmName in $Config.AttackOnlyExcludedVirtualMachines) {
            $vm = $Config.VirtualMachines[$vmName]
            $vmxPath = if ($null -ne $vm) { [string] $vm.VmxPath } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($vmxPath) -and $vmxPath -in $runningVmPaths) {
                $excludedRunning.Add([string] $vmName)
            }
        }
    }
    if ($excludedRunning.Count -gt 0) {
        throw "Attack-only preparation refused because monitoring VMs are running: $($excludedRunning.ToArray() -join ', '). Shut them down cleanly, then run Prepare again. The replay runner will not stop them automatically."
    }

    $results = New-Object System.Collections.Generic.List[object]
    $startDelaySeconds = if ($Config.ContainsKey('VmStartDelaySeconds')) {
        [Math]::Max(0, [Math]::Min(30, [int] $Config.VmStartDelaySeconds))
    }
    else {
        10
    }

    foreach ($vmName in $ScenarioDefinition.RequiredVirtualMachines) {
        $vm = $Config.VirtualMachines[$vmName]
        if ($null -eq $vm -or [string]::IsNullOrWhiteSpace([string] $vm.VmxPath)) {
            throw "VMX path is not configured for required VM: $vmName"
        }

        $vmxPath = [string] $vm.VmxPath
        if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
            throw "VMX file was not found for ${vmName}: $vmxPath"
        }

        if ($vmxPath -in $runningVmPaths) {
            $results.Add([pscustomobject]@{
                VirtualMachine = $vmName
                Action = 'UNCHANGED'
                Result = 'ALREADY_RUNNING'
                VmxPath = $vmxPath
            })
            continue
        }

        Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'vm_start_requested' -Data @{
            virtual_machine = $vmName
            vmx_path = $vmxPath
        }

        $output = & $vmRunPath start $vmxPath nogui 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start ${vmName}: $($output -join ' ')"
        }

        $results.Add([pscustomobject]@{
            VirtualMachine = $vmName
            Action = 'STARTED'
            Result = 'START_REQUEST_ACCEPTED'
            VmxPath = $vmxPath
        })

        # Avoid launching multiple heavyweight guests at the exact same time.
        if ($startDelaySeconds -gt 0) {
            Start-Sleep -Seconds $startDelaySeconds
        }
    }

    $summary = [pscustomobject]@{
        RunId = $Context.RunId
        Scenario = $ScenarioDefinition.Name
        Results = $results.ToArray()
        ImportantNote = 'VMware start acceptance does not mean guest services are ready. Run Status again after the guests finish booting.'
    }
    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'vm_preparation_completed' -Data $summary
    $summary
}

function Invoke-KaliAttackPathPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $sshPath = [string] $Config.Tools.SshPath
    if ($null -eq (Get-Command $sshPath -ErrorAction SilentlyContinue)) {
        throw "SSH client was not found: $sshPath"
    }

    $helperPath = Join-Path $ToolkitRoot 'remote\kali\pb05-path-preflight.sh'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Kali PB05 preflight helper was not found: $helperPath"
    }

    $kaliAddress = [string] $Config.Hosts.Kali.Address
    $kaliPort = [int] $Config.Hosts.Kali.SshPort
    $kaliUser = [string] $Config.Hosts.Kali.SshUser
    $windowsAddress = [string] $Config.Hosts.Windows10.Address
    $windowsPort = [int] $Config.Hosts.Windows10.WinRmPort
    $socksPort = [int] $Config.Pivots.DvwaSocksPort
    $sshTarget = "${kaliUser}@${kaliAddress}"
    # Windows PowerShell appends CRLF when streaming text to a native process.
    # Strip carriage returns on Kali before Bash parses the helper.
    $remoteCommand = "tr -d '\r' | bash -s -- '$windowsAddress' '$windowsPort' '$socksPort'"
    $helperText = [System.IO.File]::ReadAllText($helperPath).Replace("`r`n", "`n")

    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'kali_path_preflight_started' -Data @{
        kali = $kaliAddress
        windows_target = $windowsAddress
        winrm_port = $windowsPort
        socks_port = $socksPort
    }

    # SSH reads an interactive password from the console when a dedicated key
    # has not been configured. The helper body is sent over standard input and
    # is never persisted on Kali.
    $sshArguments = @(
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=5',
        '-p', [string] $kaliPort,
        $sshTarget,
        $remoteCommand
    )
    $output = $helperText | & $sshPath @sshArguments 2>&1
    $exitCode = $LASTEXITCODE

    $outputLines = @($output | ForEach-Object { [string] $_ })
    $summary = [pscustomobject]@{
        RunId = $Context.RunId
        Passed = ($exitCode -eq 0)
        ExitCode = $exitCode
        Kali = $sshTarget
        Target = "${windowsAddress}:${windowsPort}"
        SocksProxy = "127.0.0.1:${socksPort}"
        Output = $outputLines
    }

    Write-ReplayEvent -Context $Context -Level $(if ($summary.Passed) { 'INFO' } else { 'WARN' }) -Event 'kali_path_preflight_completed' -Data $summary
    $summary
}

function Invoke-KaliDmzFootholdPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $sshPath = [string] $Config.Tools.SshPath
    if ($null -eq (Get-Command $sshPath -ErrorAction SilentlyContinue)) {
        throw "SSH client was not found: $sshPath"
    }

    $helperPath = Join-Path $ToolkitRoot 'remote\kali\dmz-foothold-preflight.sh'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Kali DMZ preflight helper was not found: $helperPath"
    }

    $kaliAddress = [string] $Config.Hosts.Kali.Address
    $kaliPort = [int] $Config.Hosts.Kali.SshPort
    $kaliUser = [string] $Config.Hosts.Kali.SshUser
    $dvwaExternalAddress = [string] $Config.Hosts.Dvwa.ExternalAddress
    $dvwaExternalPort = [int] $Config.Hosts.Dvwa.ExternalPort
    $callbackPort = [int] $Config.Pivots.ChiselServerPort
    $socksPort = [int] $Config.Pivots.DvwaSocksPort
    $staticChiselPath = [string] $Config.PB05.KaliStaticChiselPath
    $staticChiselSha256 = [string] $Config.PB05.StaticChiselSha256
    $sshTarget = "${kaliUser}@${kaliAddress}"
    # Windows PowerShell appends CRLF when streaming text to a native process.
    # Strip carriage returns on Kali before Bash parses the helper.
    $remoteCommand = "tr -d '\r' | bash -s -- '$dvwaExternalAddress' '$dvwaExternalPort' '$callbackPort' '$socksPort' '$staticChiselPath' '$staticChiselSha256'"
    $helperText = [System.IO.File]::ReadAllText($helperPath).Replace("`r`n", "`n")
    $sshArguments = @(
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=5',
        '-p', [string] $kaliPort,
        $sshTarget,
        $remoteCommand
    )

    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'dmz_foothold_preflight_started' -Data @{
        kali = $kaliAddress
        dvwa_external = "${dvwaExternalAddress}:${dvwaExternalPort}"
        callback_port = $callbackPort
        socks_port = $socksPort
    }

    $output = $helperText | & $sshPath @sshArguments 2>&1
    $exitCode = $LASTEXITCODE
    $outputLines = @($output | ForEach-Object { [string] $_ })
    $summary = [pscustomobject]@{
        RunId = $Context.RunId
        Passed = ($exitCode -eq 0)
        ExitCode = $exitCode
        Kali = $sshTarget
        DvwaEntryPoint = "http://${dvwaExternalAddress}:${dvwaExternalPort}/"
        CallbackPort = $callbackPort
        SocksPort = $socksPort
        Output = $outputLines
    }

    Write-ReplayEvent -Context $Context -Level $(if ($summary.Passed) { 'INFO' } else { 'WARN' }) -Event 'dmz_foothold_preflight_completed' -Data $summary
    $summary
}

function Invoke-KaliArtifactDiscovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $sshPath = [string] $Config.Tools.SshPath
    if ($null -eq (Get-Command $sshPath -ErrorAction SilentlyContinue)) {
        throw "SSH client was not found: $sshPath"
    }

    $helperPath = Join-Path $ToolkitRoot 'remote\kali\discover-validated-commands.py'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Kali artifact-discovery helper was not found: $helperPath"
    }

    $kaliAddress = [string] $Config.Hosts.Kali.Address
    $kaliPort = [int] $Config.Hosts.Kali.SshPort
    $kaliUser = [string] $Config.Hosts.Kali.SshUser
    $sshTarget = "${kaliUser}@${kaliAddress}"
    $helperText = [System.IO.File]::ReadAllText($helperPath).Replace("`r`n", "`n")
    $sshArguments = @(
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=5',
        '-p', [string] $kaliPort,
        $sshTarget,
        "tr -d '\r' | python3 -"
    )

    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'artifact_discovery_started' -Data @{
        kali = $kaliAddress
        policy = 'fixed_sources_relevant_lines_redacted'
    }

    $output = $helperText | & $sshPath @sshArguments 2>&1
    $exitCode = $LASTEXITCODE
    $outputLines = @($output | ForEach-Object { [string] $_ })

    # Only metadata is persisted locally. Even redacted command output remains
    # console-only until a human has reviewed it.
    Write-ReplayEvent -Context $Context -Level $(if ($exitCode -eq 0) { 'INFO' } else { 'WARN' }) -Event 'artifact_discovery_completed' -Data @{
        kali = $kaliAddress
        exit_code = $exitCode
        output_line_count = $outputLines.Count
        output_persisted = $false
    }

    [pscustomobject]@{
        RunId = $Context.RunId
        Passed = ($exitCode -eq 0)
        ExitCode = $exitCode
        Output = $outputLines
    }
}

function Invoke-KaliPB05LiveReplay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $sshPath = [string] $Config.Tools.SshPath
    $scpPath = [string] $Config.Tools.ScpPath
    if ($null -eq (Get-Command $sshPath -ErrorAction SilentlyContinue)) {
        throw "SSH client was not found: $sshPath"
    }
    if ($null -eq (Get-Command $scpPath -ErrorAction SilentlyContinue)) {
        throw "SCP client was not found: $scpPath"
    }

    $helperPath = Join-Path $ToolkitRoot 'remote\kali\pb05-live-replay.sh'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Kali PB05 live helper was not found: $helperPath"
    }

    $kaliAddress = [string] $Config.Hosts.Kali.Address
    $kaliPort = [int] $Config.Hosts.Kali.SshPort
    $kaliUser = [string] $Config.Hosts.Kali.SshUser
    $sshTarget = "${kaliUser}@${kaliAddress}"
    $remoteHelper = "/tmp/pb05-live-replay-$($Context.RunId).sh"
    $temporaryHelper = [System.IO.Path]::GetTempFileName()
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    try {
        $helperText = [System.IO.File]::ReadAllText($helperPath).Replace("`r`n", "`n")
        [System.IO.File]::WriteAllText($temporaryHelper, $helperText, $utf8NoBom)
        $helperSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryHelper).Hash.ToLowerInvariant()

        Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'pb05_live_helper_stage_started' -Data @{
            kali = $kaliAddress
            remote_helper = $remoteHelper
            helper_sha256 = $helperSha256
        }

        $scpArguments = @(
            '-P', [string] $kaliPort,
            $temporaryHelper,
            "${sshTarget}:${remoteHelper}"
        )
        & $scpPath @scpArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to stage the PB05 live helper on Kali (SCP exit code $LASTEXITCODE)."
        }

        $arguments = @(
            $Context.RunId,
            $kaliAddress,
            [string] $Config.Hosts.Dvwa.ExternalAddress,
            [string] $Config.Hosts.Dvwa.ExternalPort,
            [string] $Config.Hosts.Windows10.Address,
            [string] $Config.Hosts.Windows10.WinRmPort,
            "$($Config.PB05.Domain)\$($Config.PB05.UserName)",
            [string] $Config.PB05.UserSid,
            [string] $Config.PB05.KaliStaticChiselPath,
            [string] $Config.PB05.StaticChiselSha256,
            [string] $Config.PB05.KaliWindowsChiselPath,
            [string] $Config.PB05.WindowsChiselSha256,
            [string] $Config.PB05.DvwaProxyConfig
        )
        $quotedArguments = @($arguments | ForEach-Object {
            $value = [string] $_
            if ($value.Contains("'")) {
                throw 'A PB05 live helper argument contains an unsupported single quote.'
            }
            "'$value'"
        })
        $remoteCommand = "trap 'rm -f -- $remoteHelper' EXIT; printf '%s  %s\n' '$helperSha256' '$remoteHelper' | sha256sum -c - >/dev/null; chmod 700 '$remoteHelper'; '$remoteHelper' $($quotedArguments -join ' ')"

        $sshArguments = @(
            '-q',
            '-tt',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=10',
            '-p', [string] $kaliPort,
            $sshTarget,
            $remoteCommand
        )

        $outputLines = New-Object System.Collections.Generic.List[string]
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            # OpenSSH writes normal PTY close notices to stderr. Treat native
            # stderr as captured output here and use its exit code plus the
            # explicit completion marker as the authoritative result.
            $ErrorActionPreference = 'Continue'
            & $sshPath @sshArguments 2>&1 | ForEach-Object {
                $line = ([string] $_).TrimEnd("`r")
                $outputLines.Add($line)
                Write-Host $line
            }
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $completed = $outputLines.Contains('LIVE_STATUS=PB05_ATTACK_REPLAY_COMPLETED')

        $summary = [pscustomobject]@{
            RunId = $Context.RunId
            Passed = ($exitCode -eq 0 -and $completed)
            ExitCode = $exitCode
            Output = $outputLines.ToArray()
            AttackBoundary = 'PB05_STATE_ESTABLISHED'
            MonitoringStarted = $false
            ResponseStarted = $false
        }

        Write-ReplayEvent -Context $Context -Level $(if ($summary.Passed) { 'INFO' } else { 'WARN' }) -Event 'pb05_live_replay_completed' -Data @{
            exit_code = $exitCode
            completed_marker = $completed
            monitoring_started = $false
            response_started = $false
        }
        $summary
    }
    finally {
        if (Test-Path -LiteralPath $temporaryHelper) {
            Remove-Item -LiteralPath $temporaryHelper -Force
        }
    }
}

function Invoke-KaliWIN10ServicePrivilegeEscalationReplay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $sshPath = [string] $Config.Tools.SshPath
    $scpPath = [string] $Config.Tools.ScpPath
    if ($null -eq (Get-Command $sshPath -ErrorAction SilentlyContinue)) {
        throw "SSH client was not found: $sshPath"
    }
    if ($null -eq (Get-Command $scpPath -ErrorAction SilentlyContinue)) {
        throw "SCP client was not found: $scpPath"
    }
    if (-not $Config.ContainsKey('PrivilegeEscalation')) {
        throw 'PrivilegeEscalation configuration is missing.'
    }

    $helperPath = Join-Path $ToolkitRoot 'remote\kali\win10-service-privilege-escalation.sh'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "Windows service privilege-escalation helper was not found: $helperPath"
    }

    $scenario = $Config.PrivilegeEscalation
    $kaliAddress = [string] $Config.Hosts.Kali.Address
    $kaliPort = [int] $Config.Hosts.Kali.SshPort
    $kaliUser = [string] $Config.Hosts.Kali.SshUser
    $sshTarget = "${kaliUser}@${kaliAddress}"
    $remoteHelper = "/tmp/win10-service-privesc-$($Context.RunId).sh"
    $temporaryHelper = [System.IO.Path]::GetTempFileName()
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    try {
        $helperText = [System.IO.File]::ReadAllText($helperPath).Replace("`r`n", "`n")
        [System.IO.File]::WriteAllText($temporaryHelper, $helperText, $utf8NoBom)
        $helperSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryHelper).Hash.ToLowerInvariant()

        Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'win10_service_privesc_helper_stage_started' -Data @{
            kali = $kaliAddress
            remote_helper = $remoteHelper
            helper_sha256 = $helperSha256
            service_name = [string] $scenario.ServiceName
            vulnerable_script = [string] $scenario.VulnerableScript
        }

        $scpArguments = @(
            '-P', [string] $kaliPort,
            $temporaryHelper,
            "${sshTarget}:${remoteHelper}"
        )
        & $scpPath @scpArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to stage the privilege-escalation helper on Kali (SCP exit code $LASTEXITCODE)."
        }

        $arguments = @(
            $Context.RunId,
            $kaliAddress,
            [string] $Config.Hosts.Dvwa.ExternalAddress,
            [string] $Config.Hosts.Dvwa.ExternalPort,
            [string] $Config.Hosts.Windows10.Address,
            [string] $Config.Hosts.Windows10.WinRmPort,
            "$($scenario.Domain)\$($scenario.UserName)",
            [string] $scenario.UserSid,
            [string] $Config.PB05.KaliStaticChiselPath,
            [string] $Config.PB05.StaticChiselSha256,
            [string] $Config.PB05.DvwaProxyConfig,
            [string] $scenario.ServiceName,
            [string] $scenario.ServiceExecutable,
            [string] $scenario.VulnerableScript,
            [string] $scenario.ProofArtifact,
            [string] $scenario.EventSource,
            [string] $scenario.Marker
        )
        $quotedArguments = @($arguments | ForEach-Object {
            $value = [string] $_
            if ($value.Contains("'")) {
                throw 'A privilege-escalation helper argument contains an unsupported single quote.'
            }
            "'$value'"
        })
        $remoteCommand = "trap 'rm -f -- $remoteHelper' EXIT; printf '%s  %s\n' '$helperSha256' '$remoteHelper' | sha256sum -c - >/dev/null; chmod 700 '$remoteHelper'; '$remoteHelper' $($quotedArguments -join ' ')"

        $sshArguments = @(
            '-q',
            '-tt',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=10',
            '-p', [string] $kaliPort,
            $sshTarget,
            $remoteCommand
        )

        $outputLines = New-Object System.Collections.Generic.List[string]
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $sshPath @sshArguments 2>&1 | ForEach-Object {
                $line = ([string] $_).TrimEnd("`r")
                $outputLines.Add($line)
                Write-Host $line
            }
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }

        $normalizedOutput = @($outputLines | ForEach-Object { ([string] $_).Trim() })
        $completed = $normalizedOutput -contains 'LIVE_STATUS=WINDOWS_SERVICE_PRIVESC_COMPLETED'
        $stateLine = @($normalizedOutput | Where-Object { $_.StartsWith('PRIVESC_WINDOWS_STATE=') } | Select-Object -Last 1)
        $stateValidated = $false
        $verifiedState = $null
        if ($stateLine.Count -eq 1) {
            try {
                $verifiedState = $stateLine[0].Substring('PRIVESC_WINDOWS_STATE='.Length) | ConvertFrom-Json
                $stateValidated = (
                    [string] $verifiedState.writer_sid -eq [string] $scenario.UserSid -and
                    [string] $verifiedState.executor_sid -eq 'S-1-5-18' -and
                    [string] $verifiedState.service_name -eq [string] $scenario.ServiceName -and
                    [string] $verifiedState.vulnerable_script -eq [string] $scenario.VulnerableScript -and
                    [string] $verifiedState.proof_artifact -eq [string] $scenario.ProofArtifact
                )
                if ($stateValidated) {
                    $statePath = Join-Path $Context.EvidencePath 'privilege-escalation-state.json'
                    $verifiedState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
                    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'win10_service_privesc_state_verified' -Data $verifiedState
                }
            }
            catch {
                $stateValidated = $false
            }
        }
        $summary = [pscustomobject]@{
            RunId = $Context.RunId
            Passed = ($exitCode -eq 0 -and $completed -and $stateValidated)
            ExitCode = $exitCode
            Output = $outputLines.ToArray()
            AttackBoundary = 'SVC_WEB_TO_SYSTEM_PROVED'
            StateValidated = $stateValidated
            MonitoringStarted = $false
            ResponseStarted = $false
        }

        Write-ReplayEvent -Context $Context -Level $(if ($summary.Passed) { 'INFO' } else { 'WARN' }) -Event 'win10_service_privesc_replay_completed' -Data @{
            exit_code = $exitCode
            completed_marker = $completed
            state_validated = $stateValidated
            service_name = [string] $scenario.ServiceName
            writer_identity = "$($scenario.Domain)\$($scenario.UserName)"
            expected_executor = 'NT AUTHORITY\SYSTEM'
            monitoring_started = $false
            response_started = $false
        }
        $summary
    }
    finally {
        if (Test-Path -LiteralPath $temporaryHelper) {
            Remove-Item -LiteralPath $temporaryHelper -Force
        }
    }
}

function Invoke-ReplayPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] $ScenarioDefinition,
        [Parameter(Mandatory)] $Context
    )

    Assert-ReplayLabScope -Config $Config | Out-Null
    $results = New-Object System.Collections.Generic.List[object]

    $vmRunExists = Test-Path -LiteralPath $Config.Tools.VmRunPath -PathType Leaf
    $results.Add([pscustomobject]@{
        Check = 'VMware vmrun'
        Required = $true
        Passed = $vmRunExists
        Detail = $Config.Tools.VmRunPath
    })

    foreach ($toolName in @('SshPath', 'ScpPath')) {
        $tool = [string] $Config.Tools[$toolName]
        $found = $null -ne (Get-Command $tool -ErrorAction SilentlyContinue)
        $results.Add([pscustomobject]@{
            Check = $toolName
            Required = $true
            Passed = $found
            Detail = $tool
        })
    }

    $runningVmPaths = if ($vmRunExists) { @(Get-RunningVmPaths -VmRunPath $Config.Tools.VmRunPath) } else { @() }
    foreach ($vmName in $ScenarioDefinition.RequiredVirtualMachines) {
        $vm = $Config.VirtualMachines[$vmName]
        $path = if ($null -ne $vm) { [string] $vm.VmxPath } else { '' }
        $configured = -not [string]::IsNullOrWhiteSpace($path)
        $exists = $configured -and (Test-Path -LiteralPath $path -PathType Leaf)
        $running = $exists -and ($path -in $runningVmPaths)
        $results.Add([pscustomobject]@{
            Check = "VM: $vmName"
            Required = $true
            Passed = $exists
            Detail = if (-not $configured) { 'VMX path not configured' } elseif (-not $exists) { "VMX not found: $path" } elseif ($running) { 'Configured and running' } else { 'Configured; currently stopped' }
        })
    }

    if ($Config.ContainsKey('AttackOnlyExcludedVirtualMachines')) {
        foreach ($vmName in $Config.AttackOnlyExcludedVirtualMachines) {
            $vm = $Config.VirtualMachines[$vmName]
            $path = if ($null -ne $vm) { [string] $vm.VmxPath } else { '' }
            $configured = -not [string]::IsNullOrWhiteSpace($path)
            $exists = $configured -and (Test-Path -LiteralPath $path -PathType Leaf)
            $running = $exists -and ($path -in $runningVmPaths)
            $results.Add([pscustomobject]@{
                Check = "Attack-only exclusion: $vmName off"
                Required = $true
                Passed = ($exists -and -not $running)
                Detail = if (-not $configured) { 'VMX path not configured' } elseif (-not $exists) { "VMX not found: $path" } elseif ($running) { 'RUNNING - shut down cleanly before attack replay' } else { 'Configured and stopped' }
            })
        }
    }

    $kaliReachable = Test-ReplayTcpPort -Address $Config.Hosts.Kali.Address -Port $Config.Hosts.Kali.SshPort
    $results.Add([pscustomobject]@{
        Check = 'Kali SSH from controller'
        Required = $false
        Passed = $kaliReachable
        Detail = "$($Config.Hosts.Kali.Address):$($Config.Hosts.Kali.SshPort)"
    })

    $requiredFailures = @($results | Where-Object { $_.Required -and -not $_.Passed })
    $summary = [pscustomobject]@{
        RunId = $Context.RunId
        Scenario = $ScenarioDefinition.Name
        ScopeValidated = $true
        RequiredChecksPassed = ($requiredFailures.Count -eq 0)
        # PowerShell 5.1 can fail to bind @($genericList) inside a PSCustomObject.
        Checks = $results.ToArray()
        ImportantNote = 'Attack-only scope: Splunk and Shuffle must remain off. The DMZ pivot must be checked from Kali; direct controller-to-Windows reachability is not treated as the attack path.'
    }

    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'preflight_completed' -Data $summary
    $summary
}

function Show-ReplayPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ScenarioDefinition,
        [Parameter(Mandatory)] $Context
    )

    Write-Host "Run ID: $($Context.RunId)" -ForegroundColor Cyan
    Write-Host "Scenario: $($ScenarioDefinition.Name)" -ForegroundColor Cyan
    Write-Host "Attack path: $($ScenarioDefinition.AttackPath)" -ForegroundColor Cyan
    Write-Host ''

    foreach ($step in $ScenarioDefinition.Steps) {
        $mutation = if ($step.ChangesState) { 'STATE-CHANGING' } else { 'READ-ONLY' }
        Write-Host ("{0,2}. [{1}] {2}" -f $step.Order, $mutation, $step.Name)
        Write-Host ("    {0}" -f $step.Description) -ForegroundColor DarkGray
    }

    Write-ReplayEvent -Context $Context -Level 'INFO' -Event 'dry_run_plan_rendered' -Data $ScenarioDefinition
}

Export-ModuleMember -Function @(
    'New-ReplayRunContext',
    'Write-ReplayEvent',
    'Assert-ReplayLabScope',
    'Test-ReplayTcpPort',
    'Get-RunningVmPaths',
    'Start-ReplayVirtualMachines',
    'Invoke-KaliAttackPathPreflight',
    'Invoke-KaliDmzFootholdPreflight',
    'Invoke-KaliArtifactDiscovery',
    'Invoke-KaliPB05LiveReplay',
    'Invoke-KaliWIN10ServicePrivilegeEscalationReplay',
    'Invoke-ReplayPreflight',
    'Show-ReplayPlan'
)
