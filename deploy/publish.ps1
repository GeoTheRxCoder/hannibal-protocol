<#
.SYNOPSIS
  Builds the Hannibal Protocol beta into a staging folder (run on Windows 11 with the .NET 10 SDK).
.DESCRIPTION
  Requires deploy\trust\trust-root.json (create it with tools\bootstrap_beta_signing.py).
  Code-signing of the produced executables (for example with Azure Trusted Signing)
  is a separate release step and is required before distribution beyond test machines.
#>
param([string]$Out = "$PSScriptRoot\..\artifacts\HannibalProtocol-0.6.0-beta.1",
      [string]$Configuration = "Release")
$ErrorActionPreference = 'Stop'
# Normalise once (drops "deploy\..") so SHA256SUMS paths are relative to the real staging folder.
$Out = [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out))
$root = Resolve-Path "$PSScriptRoot\.."
if (-not (Test-Path "$root\deploy\trust\trust-root.json")) {
  throw "deploy\trust\trust-root.json is missing. Run: python tools\bootstrap_beta_signing.py"
}
Write-Host "== Tests"
dotnet run --project "$root\tests\Hannibal.Core.Tests" -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Core tests failed; nothing was published." }
dotnet run --project "$root\tests\Hannibal.SmokeTests" -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Policy smoke tests failed; nothing was published." }

Remove-Item -Recurse -Force $Out -ErrorAction SilentlyContinue
$apps = @{
  'HannibalCore'    = 'src\Hannibal.CoreService\Hannibal.CoreService.csproj'
  'HannibalBroker'  = 'src\Hannibal.ContainmentBroker\Hannibal.ContainmentBroker.csproj'
  'HannibalDesktop' = 'src\Hannibal.Desktop\Hannibal.Desktop.csproj'
  'Simulator'       = 'src\Hannibal.Simulator\Hannibal.Simulator.csproj'
}
foreach ($name in $apps.Keys) {
  Write-Host "== Publish $name"
  dotnet publish "$root\$($apps[$name])" -c $Configuration -r win-x64 --self-contained false -o "$Out\$name"
  if ($LASTEXITCODE -ne 0) { throw "Publish failed for $name" }
}
Copy-Item "$PSScriptRoot\install.ps1","$PSScriptRoot\uninstall.ps1" $Out
Copy-Item "$root\docs\BETA_README.md" "$Out\README.md"
Copy-Item "$root\THIRD_PARTY_NOTICES.md" $Out
Get-ChildItem $Out -Recurse -File | Get-FileHash -Algorithm SHA256 |
  ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), $_.Path.Substring($Out.Length + 1) } |
  Set-Content "$Out\SHA256SUMS.txt"
Write-Host "Staged: $Out"
