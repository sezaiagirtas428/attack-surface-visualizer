Write-Host "=================================" -ForegroundColor Cyan
Write-Host " ATTACK SURFACE VISUALIZER " -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Starting local attack surface assessment..." -ForegroundColor Yellow
Write-Host "[*] No changes will be made to the system." -ForegroundColor Yellow
Write-Host ""
# --- Test 1: Network Discovery (Firewall Rule Group) ---
try {
    $ndRules = Get-NetFirewallRule -DisplayGroup "Network Discovery" -ErrorAction Stop
    $ndEnabledCount = ($ndRules | Where-Object { $_.Enabled -eq "True" }).Count

    if ($ndEnabledCount -gt 0) {
        Write-Host "[!] Network Discovery: ENABLED (system is more discoverable on LAN)" -ForegroundColor Red
    } else {
        Write-Host "[+] Network Discovery: DISABLED" -ForegroundColor Green
    }
} catch {
    Write-Host "[?] Network Discovery: UNKNOWN (Get-NetFirewallRule not available or access denied)" -ForegroundColor Yellow
}
Write-Host ""
# --- Test 2: Firewall Profiles ---
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop

    foreach ($p in $profiles) {
        if ($p.Enabled) {
            Write-Host "[+] Firewall $($p.Name): ENABLED" -ForegroundColor Green
        } else {
            Write-Host "[!] Firewall $($p.Name): DISABLED" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "[?] Firewall Profiles: UNKNOWN (Get-NetFirewallProfile not available or access denied)" -ForegroundColor Yellow
}
Write-Host ""
# --- Test 3: RDP Enabled ---
try {
    $rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 0) {
        Write-Host "[!] RDP: ENABLED (Remote Desktop is allowed)" -ForegroundColor Red
    } else {
        Write-Host "[+] RDP: DISABLED" -ForegroundColor Green
    }
} catch {
    Write-Host "[?] RDP: UNKNOWN (Registry access denied or key missing)" -ForegroundColor Yellow
}
Write-Host ""
function Get-DismFeatureState {
    param([Parameter(Mandatory=$true)][string]$FeatureName)

    try {
        $out = & dism.exe /Online /Get-FeatureInfo /FeatureName:$FeatureName 2>$null
        if (-not $out) { return $null }

        $line = ($out | Select-String -Pattern "State\s*:\s*" | Select-Object -First 1).ToString()
        if (-not $line) { return $null }

        return ($line -split ":\s*", 2)[1].Trim()
    } catch {
        return $null
    }
}

# --- Test 4: SMBv1 (DISM) ---
$stateSmb1 = Get-DismFeatureState -FeatureName "SMB1Protocol"
if ($stateSmb1) {
    if ($stateSmb1 -eq "Enabled") {
        Write-Host "[!] SMBv1: ENABLED (legacy and high risk)" -ForegroundColor Red
    } else {
        Write-Host "[+] SMBv1: DISABLED" -ForegroundColor Green
    }
} else {
    Write-Host "[?] SMBv1: UNKNOWN (DISM query failed)" -ForegroundColor Yellow
}
Write-Host ""

# --- Test 5: PowerShell v2 (DISM) ---
$statePSv2 = Get-DismFeatureState -FeatureName "MicrosoftWindowsPowerShellV2"
if ($statePSv2) {
    if ($statePSv2 -eq "Enabled") {
        Write-Host "[!] PowerShell v2: ENABLED (legacy and risk for LOLBins)" -ForegroundColor Red
    } else {
        Write-Host "[+] PowerShell v2: DISABLED" -ForegroundColor Green
    }
} else {
    Write-Host "[?] PowerShell v2: UNKNOWN (DISM query failed)" -ForegroundColor Yellow
}
Write-Host ""
# --- Exposure Scoring (handles UNKNOWN safely) ---
$score = 0
$reasons = New-Object System.Collections.Generic.List[string]

function Add-Risk {
    param(
        [int]$Points,
        [string]$Reason
    )
    $script:score += $Points
    $script:reasons.Add("$Reason (+$Points)") | Out-Null
}

# Network Discovery scoring
if (Get-Variable -Name ndEnabledCount -Scope Script -ErrorAction SilentlyContinue) {
    if ($ndEnabledCount -gt 0) { Add-Risk 2 "Network Discovery enabled" }
} else {
    Add-Risk 1 "Network Discovery state unknown"
}

# RDP scoring
if (Get-Variable -Name rdp -Scope Script -ErrorAction SilentlyContinue) {
    if ($rdp.fDenyTSConnections -eq 0) { Add-Risk 3 "RDP enabled" }
} else {
    Add-Risk 1 "RDP state unknown"
}

# SMBv1 scoring
if (Get-Variable -Name stateSmb1 -Scope Script -ErrorAction SilentlyContinue) {
    if ($stateSmb1 -eq "Enabled") { Add-Risk 4 "SMBv1 enabled" }
    elseif (-not $stateSmb1) { Add-Risk 1 "SMBv1 state unknown" }
} else {
    Add-Risk 1 "SMBv1 state unknown"
}

# PowerShell v2 scoring
if (Get-Variable -Name statePSv2 -Scope Script -ErrorAction SilentlyContinue) {
    if ($statePSv2 -eq "Enabled") { Add-Risk 3 "PowerShell v2 enabled" }
    elseif (-not $statePSv2) { Add-Risk 1 "PowerShell v2 state unknown" }
} else {
    Add-Risk 1 "PowerShell v2 state unknown"
}

Write-Host "---------------------------------"
Write-Host " Exposure Score"
# LOLBins scoring
if (Get-Variable -Name lolbins -Scope Script -ErrorAction SilentlyContinue) {
    $present = 0
    foreach ($b in $lolbins) { if (Test-Path $b.Path) { $present++ } }

    if ($present -ge 3) { Add-Risk 2 "Multiple LOLBins present (certutil/bitsadmin/wmic)" }
    elseif ($present -ge 1) { Add-Risk 1 "LOLBins present" }
} else {
    Add-Risk 1 "LOLBins not evaluated"
}

Write-Host "---------------------------------"

if ($reasons.Count -eq 0) {
    Write-Host "No risk signals detected from the checks performed." -ForegroundColor Green
} else {
    foreach ($r in $reasons) { Write-Host " - $r" -ForegroundColor DarkGray }
}

Write-Host ""
if ($score -ge 7) {
    Write-Host "OVERALL EXPOSURE: HIGH" -ForegroundColor Red
} elseif ($score -ge 4) {
    Write-Host "OVERALL EXPOSURE: MEDIUM" -ForegroundColor Yellow
} else {
    Write-Host "OVERALL EXPOSURE: LOW" -ForegroundColor Green
}
Write-Host ""
# --- Test 6: LOLBins Availability ---
Write-Host "---------------------------------"
Write-Host " LOLBins Availability"
Write-Host "---------------------------------"

$lolbins = @(
    @{ Name = "certutil";  Path = "$env:SystemRoot\System32\certutil.exe" },
    @{ Name = "bitsadmin"; Path = "$env:SystemRoot\System32\bitsadmin.exe" },
    @{ Name = "wmic";      Path = "$env:SystemRoot\System32\wbem\wmic.exe" }
)

foreach ($bin in $lolbins) {
    if (Test-Path $bin.Path) {
        Write-Host "[!] $($bin.Name): PRESENT (commonly abused LOLBin)" -ForegroundColor Yellow
    } else {
        Write-Host "[+] $($bin.Name): NOT PRESENT" -ForegroundColor Green
    }
}

Write-Host ""
