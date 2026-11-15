<#
.SYNOPSIS
  Removes the Hannibal Protocol beta. Removes ONLY decoy files whose content still
  matches the manifest; keeps %ProgramData%\Hannibal unless -RemoveData is given.
#>
param([string]$InstallDir = "$env:ProgramFiles\Hannibal Protocol", [switch]$RemoveData)
$ErrorActionPreference = 'Stop'
$data = Join-Path $env:ProgramData 'Hannibal'
foreach ($svc in 'HannibalCore','HannibalBroker') {
  if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force -ErrorAction SilentlyContinue; sc.exe delete $svc | Out-Null }
}
# Decoys: read the manifest and delete a decoy only if its hash is unchanged.
$db = "$data\core\core.db"
$sim = "$InstallDir\Simulator\HannibalSimulator.exe"
if ((Test-Path $db) -and (Test-Path $sim)) {
  & $sim --remove-decoys $db
} elseif (Test-Path $db) {
  Write-Warning "Simulator tool not found; decoy files were left in place. Their locations are listed in $db (table canary_manifest)."
}
Remove-LocalGroupMember -SID 'S-1-5-32-559' -Member 'NT SERVICE\HannibalCore' -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Hannibal Protocol (beta).lnk" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
if ($RemoveData) { Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue; Write-Host "Data removed." }
else { Write-Host "Data kept at $data (journal, audit chains, broker intent log). Use -RemoveData to delete it." }
