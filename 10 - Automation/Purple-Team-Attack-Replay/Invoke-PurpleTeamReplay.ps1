[CmdletBinding()]
param(
    [ValidateSet('PB05-PersistenceC2', 'WIN10-ServicePrivilegeEscalation')]
    [string] $Scenario = 'PB05-PersistenceC2',

    [ValidateSet('DryRun', 'Status', 'Preflight', 'Prepare', 'ArtifactDiscovery', 'FootholdPreflight', 'AttackPathPreflight', 'Live', 'Cleanup')]
    [string] $Mode = 'DryRun',

    [string] $ConfigPath,

    [switch] $ConfirmLive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootPath = $PSScriptRoot
$modulePath = Join-Path $rootPath 'modules\PurpleTeamReplay.psm1'
$pb05ScenarioPath = Join-Path $rootPath 'scenarios\PB05-PersistenceC2.ps1'
$privilegeEscalationScenarioPath = Join-Path $rootPath 'scenarios\WIN10-ServicePrivilegeEscalation.ps1'
$exampleConfigPath = Join-Path $rootPath 'config\lab.example.psd1'
$localConfigPath = Join-Path $rootPath 'config\lab.local.psd1'

Import-Module $modulePath -Force
. $pb05ScenarioPath
. $privilegeEscalationScenarioPath

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = if (Test-Path -LiteralPath $localConfigPath) {
        $localConfigPath
    }
    else {
        $exampleConfigPath
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Configuration file not found: $ConfigPath"
}

$usingExampleConfig = [System.IO.Path]::GetFullPath($ConfigPath) -eq [System.IO.Path]::GetFullPath($exampleConfigPath)
if ($usingExampleConfig) {
    Write-Warning 'Using lab.example.psd1. Copy it to lab.local.psd1 before enabling Live or Cleanup mode.'
}

$config = Import-PowerShellDataFile -LiteralPath $ConfigPath
$context = New-ReplayRunContext -RootPath $rootPath -Scenario $Scenario -Mode $Mode
$definition = switch ($Scenario) {
    'PB05-PersistenceC2' { Get-PB05ScenarioDefinition -Config $config }
    'WIN10-ServicePrivilegeEscalation' { Get-WIN10ServicePrivilegeEscalationScenarioDefinition -Config $config }
}

Write-ReplayEvent -Context $context -Level 'INFO' -Event 'run_started' -Data @{
    config_path = $ConfigPath
    example_config = $usingExampleConfig
}

try {
    switch ($Mode) {
        'DryRun' {
            Assert-ReplayLabScope -Config $config | Out-Null
            Show-ReplayPlan -ScenarioDefinition $definition -Context $context
        }
        'Status' {
            $result = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            $result.Checks | Format-Table Check, Required, Passed, Detail -AutoSize
            Write-Host ''
            Write-Host $result.ImportantNote -ForegroundColor Yellow
        }
        'Preflight' {
            $result = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            $result.Checks | Format-Table Check, Required, Passed, Detail -AutoSize
            if (-not $result.RequiredChecksPassed) {
                throw 'One or more required preflight checks failed. Review the table above.'
            }
            Write-Host 'Required preflight checks passed.' -ForegroundColor Green
        }
        'Prepare' {
            $preflight = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            if (-not $preflight.RequiredChecksPassed) {
                $preflight.Checks | Format-Table Check, Required, Passed, Detail -AutoSize
                throw 'Required preflight checks failed; no VM start was attempted.'
            }

            $result = Start-ReplayVirtualMachines -Config $config -ScenarioDefinition $definition -Context $context
            $result.Results | Format-Table VirtualMachine, Action, Result, VmxPath -AutoSize
            Write-Host ''
            Write-Host $result.ImportantNote -ForegroundColor Yellow
        }
        'AttackPathPreflight' {
            $preflight = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            if (-not $preflight.RequiredChecksPassed) {
                $preflight.Checks | Format-Table Check, Required, Passed, Detail -AutoSize
                throw 'Required local preflight checks failed.'
            }
            if (-not ($preflight.Checks | Where-Object { $_.Check -eq 'Kali SSH from controller' }).Passed) {
                throw 'Kali SSH is not reachable from the controller.'
            }

            $result = Invoke-KaliAttackPathPreflight -Config $config -ToolkitRoot $rootPath -Context $context
            $result.Output | ForEach-Object { Write-Host $_ }
            if (-not $result.Passed) {
                throw "PB05 attack-path preflight failed closed with remote exit code $($result.ExitCode)."
            }
            Write-Host "$Scenario attack path is ready." -ForegroundColor Green
        }
        'FootholdPreflight' {
            $preflight = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            if (-not $preflight.RequiredChecksPassed) {
                $preflight.Checks | Format-Table Check, Required, Passed, Detail -AutoSize
                throw 'Required local preflight checks failed.'
            }
            if (-not ($preflight.Checks | Where-Object { $_.Check -eq 'Kali SSH from controller' }).Passed) {
                throw 'Kali SSH is not reachable from the controller.'
            }

            $result = Invoke-KaliDmzFootholdPreflight -Config $config -ToolkitRoot $rootPath -Context $context
            $result.Output | ForEach-Object { Write-Host $_ }
            if (-not $result.Passed) {
                throw "DMZ foothold preflight failed closed with remote exit code $($result.ExitCode)."
            }
            Write-Host 'DMZ foothold prerequisites are ready.' -ForegroundColor Green
        }
        'ArtifactDiscovery' {
            $preflight = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            if (-not ($preflight.Checks | Where-Object { $_.Check -eq 'Kali SSH from controller' }).Passed) {
                throw 'Kali SSH is not reachable from the controller.'
            }

            $result = Invoke-KaliArtifactDiscovery -Config $config -ToolkitRoot $rootPath -Context $context
            $result.Output | ForEach-Object { Write-Host $_ }
            if (-not $result.Passed) {
                throw "Artifact discovery failed with remote exit code $($result.ExitCode)."
            }
            Write-Host 'Artifact discovery completed. Review the console output before preserving any command.' -ForegroundColor Green
        }
        'Live' {
            if ($usingExampleConfig) {
                throw 'Live mode requires config\lab.local.psd1.'
            }
            if (-not $config.EnableLiveExecution) {
                throw 'Live mode is disabled in the local configuration.'
            }
            if (-not $ConfirmLive) {
                throw 'Live mode requires the explicit -ConfirmLive switch.'
            }

            $preflight = Invoke-ReplayPreflight -Config $config -ScenarioDefinition $definition -Context $context
            if (-not $preflight.RequiredChecksPassed) {
                $preflight.Checks | Format-Table Check, Required, Passed, Detail -AutoSize
                throw 'Required local preflight checks failed. No live action was attempted.'
            }
            if (-not ($preflight.Checks | Where-Object { $_.Check -eq 'Kali SSH from controller' }).Passed) {
                throw 'Kali SSH is not reachable from the controller. No live action was attempted.'
            }

            $runningVmPaths = @(Get-RunningVmPaths -VmRunPath $config.Tools.VmRunPath)
            $stoppedRequiredVms = @($definition.RequiredVirtualMachines | Where-Object {
                [string] $config.VirtualMachines[$_].VmxPath -notin $runningVmPaths
            })
            if ($stoppedRequiredVms.Count -gt 0) {
                throw "Live mode requires every attack VM to be running. Currently stopped: $($stoppedRequiredVms -join ', ')."
            }

            switch ($Scenario) {
                'PB05-PersistenceC2' {
                    Invoke-PB05LiveScenario -Config $config -ToolkitRoot $rootPath -Context $context
                }
                'WIN10-ServicePrivilegeEscalation' {
                    Invoke-WIN10ServicePrivilegeEscalationLiveScenario -Config $config -ToolkitRoot $rootPath -Context $context
                }
            }
        }
        'Cleanup' {
            if ($usingExampleConfig) {
                throw 'Cleanup mode requires config\lab.local.psd1.'
            }
            Assert-ReplayLabScope -Config $config | Out-Null
            switch ($Scenario) {
                'PB05-PersistenceC2' {
                    Invoke-PB05CleanupScenario -Config $config -Context $context
                }
                'WIN10-ServicePrivilegeEscalation' {
                    Invoke-WIN10ServicePrivilegeEscalationCleanupScenario -Config $config -ToolkitRoot $rootPath -Context $context
                }
            }
        }
    }

    Write-ReplayEvent -Context $context -Level 'INFO' -Event 'run_completed'
}
catch {
    Write-ReplayEvent -Context $context -Level 'ERROR' -Event 'run_failed' -Data @{
        message = $_.Exception.Message
    }
    throw
}
finally {
    Write-Host ''
    Write-Host "Evidence: $($context.EvidencePath)" -ForegroundColor DarkGray
}
