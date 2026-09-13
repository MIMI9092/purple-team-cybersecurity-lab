[CmdletBinding()]
param(
    [switch] $ResetOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Use the built-in Windows PowerShell (powershell.exe), not PowerShell 7 (pwsh), for the .NET Framework service-wrapper build.'
}

$serviceName = 'PFA-Lab-Updater'
$serviceDisplayName = 'PFA Lab Updater'
$serviceDirectory = 'C:\Program Files\PFA-Lab'
$serviceExecutable = Join-Path $serviceDirectory 'PFA-Lab-Updater.exe'
$fixtureDirectory = 'C:\ProgramData\PFA-Lab\PrivilegeEscalation'
$vulnerableScript = Join-Path $fixtureDirectory 'PFA-Lab-Updater.ps1'
$proofArtifact = Join-Path $fixtureDirectory 'system-proof.json'
$manifestPath = Join-Path $fixtureDirectory 'fixture-manifest.json'
$eventSource = 'PFA-Lab-PrivilegeEscalation'
$delegatedAccount = 'LAB\svc_web'
$expectedUserSid = 'S-1-5-21-722403993-16450863-2166090910-1106'
$systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$userSid = New-Object System.Security.Principal.SecurityIdentifier($expectedUserSid)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Assert-ElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated Windows PowerShell session on WIN10-CLIENT01.'
    }
}

function Invoke-ScChecked {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    $output = @(& sc.exe @Arguments 2>&1 | ForEach-Object { [string] $_ })
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed (exit $LASTEXITCODE): $($output -join ' | ')"
    }
    $output
}

function Get-ServiceConfiguration {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return $null
    }
    if ([string] $service.PathName -notlike "*$serviceExecutable*") {
        throw "Refusing to touch existing service '$serviceName' because its executable is not the PFA lab wrapper: $($service.PathName)"
    }
    $service
}

function Stop-LabServiceIfNeeded {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

function Get-BaselineScriptText {
@'
$ErrorActionPreference = 'Stop'
$Marker = 'PFA_PRIVESC_BASELINE_V1'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Message = "$Marker execution_identity=$($Identity.Name) execution_sid=$($Identity.User.Value) timestamp_utc=$((Get-Date).ToUniversalTime().ToString('o'))"
Write-EventLog -LogName Application -Source 'PFA-Lab-PrivilegeEscalation' -EventId 9100 -EntryType Information -Message $Message
'@
}

function Set-FixturePermissions {
    $directoryAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $directoryAcl.SetOwner($administratorsSid)
    $directoryAcl.SetAccessRuleProtection($true, $false)
    $directoryAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $directoryAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $directoryAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($userSid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $fixtureDirectory -AclObject $directoryAcl

    $fileAcl = New-Object System.Security.AccessControl.FileSecurity
    $fileAcl.SetOwner($administratorsSid)
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', 'Allow')))
    $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, 'FullControl', 'Allow')))
    $fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($userSid, 'Modify', 'Allow')))
    $fileAcl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule($userSid, 'Write,Delete,ChangePermissions', 'Success')))
    Set-Acl -LiteralPath $vulnerableScript -AclObject $fileAcl
}

function Set-ServiceStartDelegation {
    $sddlLines = Invoke-ScChecked -Arguments @('sdshow', $serviceName)
    $sddl = [string] ($sddlLines | Where-Object { $_ -match '^D:' } | Select-Object -Last 1)
    if ([string]::IsNullOrWhiteSpace($sddl)) {
        throw 'The service security descriptor could not be read.'
    }

    $delegatedAce = "(A;;CCLCRPRC;;;$expectedUserSid)"
    if ($sddl.Contains($delegatedAce)) {
        return
    }

    $saclIndex = $sddl.IndexOf('S:')
    $updatedSddl = if ($saclIndex -ge 0) {
        $sddl.Substring(0, $saclIndex) + $delegatedAce + $sddl.Substring($saclIndex)
    }
    else {
        $sddl + $delegatedAce
    }
    Invoke-ScChecked -Arguments @('sdset', $serviceName, $updatedSddl) | Out-Null
}

function Install-ServiceWrapper {
    New-Item -ItemType Directory -Path $serviceDirectory -Force | Out-Null
    $temporaryExecutable = Join-Path $env:TEMP "PFA-Lab-Updater-$([guid]::NewGuid().ToString('N')).exe"
    $escapedScript = $vulnerableScript.Replace('\', '\\')
    $source = @"
using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

public sealed class PfaLabUpdaterService : ServiceBase
{
    public PfaLabUpdaterService()
    {
        ServiceName = "$serviceName";
        CanStop = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                var startInfo = new ProcessStartInfo();
                startInfo.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
                startInfo.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"$escapedScript\"";
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                using (var child = Process.Start(startInfo))
                {
                    if (child != null)
                    {
                        child.WaitForExit(60000);
                    }
                }
            }
            finally
            {
                try { Stop(); } catch { }
            }
        });
    }

    public static void Main()
    {
        ServiceBase.Run(new PfaLabUpdaterService());
    }
}
"@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $temporaryExecutable -OutputType WindowsApplication -ReferencedAssemblies 'System.ServiceProcess.dll'
        if (-not (Test-Path -LiteralPath $temporaryExecutable -PathType Leaf)) {
            throw 'The service wrapper compiler did not create an executable.'
        }
        Move-Item -LiteralPath $temporaryExecutable -Destination $serviceExecutable -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryExecutable) {
            Remove-Item -LiteralPath $temporaryExecutable -Force
        }
    }
}

Assert-ElevatedAdministrator

$translatedSid = (New-Object System.Security.Principal.NTAccount($delegatedAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
if ($translatedSid -ne $expectedUserSid) {
    throw "The delegated account SID is not the documented lab SID. Expected $expectedUserSid but resolved $translatedSid."
}

$existingService = Get-ServiceConfiguration
if ($ResetOnly -and $null -eq $existingService) {
    throw "Reset refused because the lab service '$serviceName' is not installed."
}

Stop-LabServiceIfNeeded

if (-not $ResetOnly) {
    if ($null -ne $existingService) {
        Invoke-ScChecked -Arguments @('delete', $serviceName) | Out-Null
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            throw "The previous lab service '$serviceName' is still pending deletion. Reboot WIN10-CLIENT01, then run the installer again."
        }
    }

    Install-ServiceWrapper
    $createResult = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
        Name = $serviceName
        DisplayName = $serviceDisplayName
        PathName = "`"$serviceExecutable`""
        ServiceType = [byte] 16
        ErrorControl = [byte] 1
        StartMode = 'Manual'
        DesktopInteract = $false
        StartName = 'LocalSystem'
        StartPassword = $null
    }
    if ([int] $createResult.ReturnValue -ne 0) {
        throw "Win32_Service.Create failed with return value $($createResult.ReturnValue)."
    }
    Invoke-ScChecked -Arguments @('description', $serviceName, 'PFA lab-only service for deterministic writable-script privilege-escalation telemetry.') | Out-Null
}

New-Item -ItemType Directory -Path $fixtureDirectory -Force | Out-Null
$baselineText = (Get-BaselineScriptText).Replace("`r`n", "`n").Replace("`n", "`r`n") + "`r`n"
[IO.File]::WriteAllText($vulnerableScript, $baselineText, $utf8NoBom)
if (Test-Path -LiteralPath $proofArtifact) {
    Remove-Item -LiteralPath $proofArtifact -Force
}

if ([Diagnostics.EventLog]::SourceExists($eventSource)) {
    $registeredLog = [Diagnostics.EventLog]::LogNameFromSourceName($eventSource, '.')
    if ($registeredLog -ne 'Application') {
        throw "Event source '$eventSource' already belongs to unexpected log '$registeredLog'."
    }
}
else {
    New-EventLog -LogName Application -Source $eventSource
}

# These audit settings are intentionally retained during cleanup because they
# improve defensive visibility and may predate this fixture.
& auditpol.exe /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' '/success:enable' '/failure:disable' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to enable File System success auditing.' }
& auditpol.exe /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' '/success:enable' '/failure:disable' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to enable Process Creation success auditing.' }
New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null

Set-FixturePermissions
Set-ServiceStartDelegation

$manifest = [ordered]@{
    schema_version = 'PFA_PRIVESC_FIXTURE_V1'
    installed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    reset_only = [bool] $ResetOnly
    service_name = $serviceName
    service_executable = $serviceExecutable
    service_executable_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $serviceExecutable).Hash
    service_account = 'LocalSystem'
    delegated_account = $delegatedAccount
    delegated_sid = $expectedUserSid
    delegated_service_rights = 'QUERY_CONFIG, QUERY_STATUS, START, READ_CONTROL'
    vulnerable_script = $vulnerableScript
    vulnerable_script_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $vulnerableScript).Hash
    proof_artifact = $proofArtifact
    event_source = $eventSource
    telemetry = @('Security 4663', 'Security 4688', 'PowerShell 4104', 'System 7036', 'Application 9101')
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), $utf8NoBom)

$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
$scriptAcl = Get-Acl -LiteralPath $vulnerableScript -Audit
[pscustomobject]@{
    FixtureStatus = if ($ResetOnly) { 'RESET_READY' } else { 'INSTALLED_READY' }
    ServiceName = $service.Name
    ServiceAccount = $service.StartName
    ServiceState = $service.State
    ServiceExecutable = $serviceExecutable
    VulnerableScript = $vulnerableScript
    VulnerableScriptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $vulnerableScript).Hash
    DelegatedIdentity = $delegatedAccount
    DelegatedSid = $translatedSid
    AuditRuleCount = @($scriptAcl.Audit).Count
    ProofPresent = Test-Path -LiteralPath $proofArtifact
    Manifest = $manifestPath
}
