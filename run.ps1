# Attack Surface Visualizer - launcher
# Downloads and runs the latest asv.ps1 from this repository (read-only checks)

$ErrorActionPreference = "Stop"

$repo = "sezaiagirtas428/attack-surface-visualizer"
$base = "https://raw.githubusercontent.com/$repo/main"

$tmpDir = Join-Path $env:TEMP "attack-surface-visualizer"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

$asvPath = Join-Path $tmpDir "asv.ps1"
$asvUrl  = "$base/asv.ps1"

Write-Host "[*] Attack Surface Visualizer (launcher)" -ForegroundColor Cyan
Write-Host "[*] Downloading: $asvUrl" -ForegroundColor Yellow

Invoke-WebRequest -UseBasicParsing -Uri $asvUrl -OutFile $asvPath

Write-Host "[*] Running assessment (read-only)..." -ForegroundColor Yellow
& powershell -ExecutionPolicy Bypass -File $asvPath
