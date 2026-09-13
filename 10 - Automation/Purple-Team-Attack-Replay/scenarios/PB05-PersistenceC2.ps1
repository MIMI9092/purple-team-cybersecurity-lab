Set-StrictMode -Version Latest

function Get-PB05ScenarioDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    [pscustomobject]@{
        Name = 'PB05-PersistenceC2'
        DisplayName = 'PB05 Persistence and C2 Replay'
        Scope = 'ATTACK_ONLY'
        AttackPath = 'Windows controller -> Kali -> DVWA SOCKS 1080 -> pypsrp -> WIN10-CLIENT01'
        # Startup order prevents the endpoint and attacker from racing the
        # network appliances during a cold lab start.
        # The GNS3 desktop application manages the GNS3 VM. The replay runner
        # must not start that VM independently.
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
                Name = 'Start only the PB05-required virtual machines'
                Description = 'Start OPNsense, the local DMZ-DVWA VMware guest, Kali, AD-DC01 and WIN10-CLIENT01 when stopped. GNS3 manages its own VM; Splunk and Shuffle must remain off.'
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 3
                Name = 'Check the existing DMZ foothold and SOCKS pivot'
                Description = "From Kali, verify the Chisel SOCKS listener on 127.0.0.1:$($Config.Pivots.DvwaSocksPort) and WinRM through that pivot."
                ChangesState = $false
            }
            [pscustomobject]@{
                Order = 4
                Name = 'Open the controlled remote Windows session from Kali'
                Description = "Use pypsrp with the Microsoft.PowerShell endpoint through the temporary loopback relay and DMZ SOCKS pivot to reach $($Config.Hosts.Windows10.Name); do not use direct controller-side WinRM."
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 5
                Name = 'Create the scoped PB05 persistence artifacts'
                Description = "Through the remote shell, create only Run value '$($Config.PB05.RunValueName)' and the documented persistence script for LAB\$($Config.PB05.UserName)."
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 6
                Name = 'Launch the controlled Chisel callback'
                Description = "Start only $($Config.PB05.ChiselPath), callback to $($Config.PB05.CallbackAddress):$($Config.PB05.CallbackPort), reverse SOCKS $($Config.PB05.ReverseSocksPort)."
                ChangesState = $true
            }
            [pscustomobject]@{
                Order = 7
                Name = 'Validate attacker-side observable state'
                Description = "Verify Kali listener 127.0.0.1:$($Config.PB05.ReverseSocksPort) and record timestamps without collecting secrets."
                ChangesState = $false
            }
            [pscustomobject]@{
                Order = 8
                Name = 'Record the attack-chain handoff state'
                Description = 'Record the exact persistence, process, callback and pivot state, then stop. Detection, Shuffle execution, analyst approval, containment and cleanup are outside this attack-only replay.'
                ChangesState = $false
            }
        )
    }
}

function Invoke-PB05LiveScenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ToolkitRoot,
        [Parameter(Mandatory)] $Context
    )

    $result = Invoke-KaliPB05LiveReplay -Config $Config -ToolkitRoot $ToolkitRoot -Context $Context
    if (-not $result.Passed) {
        throw "PB05 live replay failed closed with remote exit code $($result.ExitCode)."
    }

    Write-Host 'PB05 attack state was established and verified.' -ForegroundColor Green
    Write-Host 'The replay stopped at the attack boundary; Splunk, Shuffle, approval, containment and cleanup were not started.' -ForegroundColor Yellow
    $result
}

function Invoke-PB05CleanupScenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] $Context
    )

    throw @'
PB05 Cleanup mode is intentionally locked until the live runner can identify
the exact process creation time, path, command line, user, and Run value data.
This prevents broad process termination or registry deletion.
'@
}
