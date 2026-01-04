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
# --- Test 4: SMBv1 ---
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    if ($smb1.State -eq "Enabled") {
        Write-Host "[!] SMBv1: ENABLED (legacy and high risk)" -ForegroundColor Red
    } else {
        Write-Host "[+] SMBv1: DISABLED" -ForegroundColor Green
    }
} catch {
    Write-Host "[?] SMBv1: UNKNOWN (feature query failed or access denied)" -ForegroundColor Yellow
}
Write-Host ""
