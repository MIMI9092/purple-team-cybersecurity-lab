Set-StrictMode -Version Latest

function Get-WIN10ServicePrivilegeEscalationScenarioDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    if (-not $Config.ContainsKey('PrivilegeEscalation')) {
        throw 'PrivilegeEscalation configuration is missing.'
    }

    $scenario = $Config.PrivilegeEscalation
    [pscustomobject]@{
        Name = 'WIN10-ServicePrivilegeEscalation'
        DisplayName = 'WIN10 Writable Service Script Privilege Escalation'
        Scope = 'ATTACK_ONLY'
        AttackPath = 'Windows controller -> Kali -> DVWA SOCKS 1080 -> pypsrp as LAB\svc_web -> lab service -> NT AUTHORITY\SYSTEM'
        RequiredVirtualMachines = @('OPNsense', 'Dvwa', 'Kali', 'ActiveDirectory', 'Windows10')
        Steps = @(
            [pscustomobject]@{
                Order = 1
                Name = 'Validate the fixed lab scope and local tools'
                Description = 'Reject any address outside the documented CBI lab and verify vmrun, SSH and SCP.'
                ChangesState = $false
            }
            [pscustomobject]@{
                Order = 2
                Name = 'Start only the attack-chain virtual machines'
                Description = 'Start OPNsense, the local DMZ-DVWA guest, Kali, AD-DC01 and WIN10-CLIENT01 when stopped. Splunk and Shuffle remain off.'
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 3
                Name = 'Validate the existing DMZ pivot and lab fixture'
                Description = "Reach WinRM only through SOCKS 1080 and verify the exact service '$($scenario.ServiceName)', protected wrapper and writable script path."
                ChangesState = $false
            }
            [pscustomobject]@{
                Order = 4
                Name = 'Capture the pre-escalation identity and baseline'
                Description = "Record LAB\$($scenario.UserName), its SID, the vulnerable file hash, ACL, service state and UTC timestamp before modification."
                ChangesState = $false
            }
            [pscustomobject]@{
                Order = 5
                Name = 'Modify only the vulnerable lab service script'
                Description = "As LAB\$($scenario.UserName), replace only '$($scenario.VulnerableScript)' with the hash-verified proof payload."
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 6
                Name = 'Start only the approved lab service'
                Description = "Use the deliberately delegated SERVICE_START permission on '$($scenario.ServiceName)'; do not create, reconfigure or replace the service executable."
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 7
                Name = 'Verify SYSTEM execution and preserve correlation evidence'
                Description = "Validate '$($scenario.ProofArtifact)', the SYSTEM SID, payload hash and Application event while preserving Security 4663, 4688, PowerShell 4104 and Service Control Manager telemetry for later Splunk ingestion."
                ChangesState = $false
            }
            [pscustomobject]@{
                Order = 8
                Name = 'Stop at the privilege-escalation boundary'
                Description = 'Record the svc_web writer and SYSTEM executor as separate identities. Monitoring, response and cleanup are not started.'
                ChangesState = $false
            }
        )
    }
}

function Invoke-WIN10ServicePrivilegeEscalationLiveScenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    $result = Invoke-KaliWIN10ServicePrivilegeEscalationReplay -Config $Config -ToolkitRoot $ToolkitRoot -Context $Context
    if (-not $result.Passed) {
        throw "Windows service privilege-escalation replay failed closed with remote exit code $($result.ExitCode)."
    }

    Write-Host 'The controlled LAB\svc_web to NT AUTHORITY\SYSTEM transition was established and verified.' -ForegroundColor Green
    Write-Host 'The modified file and proof remain in place for later Splunk validation. Run the elevated reset script on WIN10-CLIENT01 before repeating the scenario.' -ForegroundColor Yellow
    $result
}

function Invoke-WIN10ServicePrivilegeEscalationCleanupScenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    $resetScript = Join-Path $ToolkitRoot 'windows\Reset-PfaLabPrivilegeEscalation.ps1'
    Write-ReplayEvent -Context $Context -Level 'WARN' -Event 'win10_service_privesc_cleanup_requires_local_admin' -Data @{
        reset_script = $resetScript
        target = [string] $Config.Hosts.Windows10.Name
    }
    throw "Cleanup requires a local elevated PowerShell session on $($Config.Hosts.Windows10.Name). Copy and run: $resetScript"
}
