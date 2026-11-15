<#
.SYNOPSIS
  Installs the Hannibal Protocol 0.6.0-beta.1 (SIMULATION) on a Windows 11 TEST machine.
.DESCRIPTION
  Run from an elevated PowerShell inside the folder produced by publish.ps1.
  - Installs two services: HannibalBroker (LocalSystem, simulation only - it has no
    effector) and HannibalCore (virtual account NT SERVICE\HannibalCore).
  - Creates %ProgramData%\Hannibal with restricted ACLs.
  - Copies signed bundles from -Bundles into %ProgramData%\Hannibal\bundles.
  - Does NOT deploy decoy files unless -DeployDecoys is given.
  - Does NOT change Microsoft Defender, the firewall, or any other security setting.
  Use only on machines you own or are authorized to test. Prefer a VM snapshot.
#>
param([Parameter(Mandatory)] [string]$Bundles,
      [string]$InstallDir = "$env:ProgramFiles\Hannibal Protocol",
      [switch]$DeployDecoys,
      [switch]$EnableSysmonNote)
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated PowerShell."
}
$here = $PSScriptRoot
$data = Join-Path $env:ProgramData 'Hannibal'
$coreAcct = 'NT SERVICE\HannibalCore'

Write-Host "Hannibal Protocol 0.6.0-beta.1 - SIMULATION build. No containment action changes this machine."

# 1. Program files (read-only for services).
New-Item -ItemType Directory -Force $InstallDir | Out-Null
foreach ($d in 'HannibalCore','HannibalBroker','HannibalDesktop','Simulator') {
  Copy-Item -Recurse -Force (Join-Path $here $d) $InstallDir
}
if (-not (Test-Path "$InstallDir\HannibalCore\trust\trust-root.json")) { throw "trust-root.json missing from the build." }

# 2. Services. Broker first: it creates the IPC session key.
foreach ($svc in 'HannibalCore','HannibalBroker') {
  if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force -ErrorAction SilentlyContinue; sc.exe delete $svc | Out-Null; Start-Sleep 2 }
}
sc.exe create HannibalBroker binPath= "`"$InstallDir\HannibalBroker\HannibalBroker.exe`"" start= auto DisplayName= "Hannibal Protocol Broker (simulation)" | Out-Null
sc.exe description HannibalBroker "Re-verifies and records Hannibal Protocol containment requests. Beta: simulation only, no system changes." | Out-Null
sc.exe create HannibalCore binPath= "`"$InstallDir\HannibalCore\HannibalCoreService.exe`"" obj= "$coreAcct" start= auto depend= HannibalBroker DisplayName= "Hannibal Protocol Core (simulation)" | Out-Null
sc.exe description HannibalCore "Hannibal Protocol agents: telemetry, decoys, analysis and policy. Beta: advisory only." | Out-Null
sc.exe failure HannibalBroker reset= 86400 actions= restart/5000/restart/30000// | Out-Null
sc.exe failure HannibalCore reset= 86400 actions= restart/5000/restart/30000// | Out-Null
# Real-time kernel ETW sessions need Performance Log Users membership (or administrator).
# VERIFY on your build that this is sufficient for the Microsoft-Windows-Kernel-* providers.
try { Add-LocalGroupMember -SID 'S-1-5-32-559' -Member $coreAcct -ErrorAction Stop } catch { Write-Warning "Could not add $coreAcct to Performance Log Users: $_" }

# 3. Data directories and ACLs.
function Set-Acl2($path, [string[]]$rules) {
  New-Item -ItemType Directory -Force $path | Out-Null
  icacls $path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' @rules | Out-Null
}
Set-Acl2 $data @()
Set-Acl2 "$data\core"    @("${coreAcct}:(OI)(CI)M")
Set-Acl2 "$data\bundles" @("${coreAcct}:(OI)(CI)RX")
Set-Acl2 "$data\status"  @("${coreAcct}:(OI)(CI)M", 'Users:(OI)(CI)RX')   # the dashboard reads this, nothing else
icacls $data /grant "${coreAcct}:RX" 'Users:RX' | Out-Null                  # traverse only; subfolders keep their own ACLs
# broker\ and ipc\ are created and locked down by the broker itself on first start.

# 4. Signed bundles (verified by BOTH services at start; unsigned or tampered bundles are refused).
foreach ($f in 'policy.json','policy.json.sig','indicators.json','indicators.json.sig') {
  $src = Join-Path $Bundles $f
  if (-not (Test-Path $src)) { throw "Missing $src. Create bundles with tools\bootstrap_beta_signing.py." }
  Copy-Item $src "$data\bundles\$f" -Force
}

# 5. Start services.
Start-Service HannibalBroker; Start-Sleep 3; Start-Service HannibalCore; Start-Sleep 3

# 6. Decoys (opt-in). Placed by this ELEVATED step; the Core service's account cannot write to user folders.
if ($DeployDecoys) {
  Write-Host "Creating decoy files (hidden, not indexed) in local Documents/Desktop/Pictures folders that are not OneDrive-redirected."
  & "$InstallDir\Simulator\HannibalSimulator.exe" --deploy-decoys
  if ($LASTEXITCODE -ne 0) { Write-Warning "Decoy deployment failed; the rest of the installation is unaffected." }
}

# 7. Shortcut.
$lnk = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Hannibal Protocol (beta).lnk")
$lnk.TargetPath = "$InstallDir\HannibalDesktop\HannibalDesktop.exe"; $lnk.Save()

Write-Host ""
Write-Host "Installed. Dashboard: Start menu > Hannibal Protocol (beta)."
Write-Host "Logs: Event Viewer > Windows Logs > Application (sources HannibalCore / HannibalBroker)."
Write-Host "Microsoft Defender remains your active antivirus. Hannibal Protocol does not replace it."
if ($EnableSysmonNote) { Write-Host "Optional second capture channel: native Sysmon (Windows 11 optional feature). Enable it yourself only if you want it; the installer never does." }
