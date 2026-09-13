[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installer = Join-Path $PSScriptRoot 'Install-PfaLabPrivilegeEscalation.ps1'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Fixture installer not found beside the reset script: $installer"
}

& $installer -ResetOnly
