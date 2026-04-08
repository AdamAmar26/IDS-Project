param(
  [Parameter(Mandatory=$true)][string]$IpAddress,
  [switch]$DryRun
)

$ruleName = "IDS_Block_$IpAddress"
$cmd = "netsh advfirewall firewall add rule name=$ruleName dir=out action=block remoteip=$IpAddress"

if ($DryRun) {
  Write-Host "DRY RUN: $cmd"
  exit 0
}

Invoke-Expression $cmd
Write-Host "Blocked outbound IP: $IpAddress"
