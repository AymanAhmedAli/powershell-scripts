# ================================
# fix_krbtgt_rotation.ps1
# Author: Ayman Ahmed
# Description: Rotates krbtgt account password safely
#              Must be run TWICE with 10+ hour gap between runs
# Usage: .\fixes\fix_krbtgt_rotation.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
#               Run on PDC Emulator DC
#
# CRITICAL WARNING:
#   Most sensitive fix in AD security.
#   Wrong execution can break ALL Kerberos authentication.
#
# Process:
#   Run 1: Rotate password
#   Wait:  10+ hours (DCs replicate + tickets expire)
#   Run 2: Rotate again (fully invalidates old tickets)
# ================================

$WhatIf = $true  # Change to $false to rotate

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: krbtgt Password Rotation" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Step 1: Pre-flight checks
Write-Host "`n[STEP 1] Pre-flight checks..." -ForegroundColor Yellow

$pdc = (Get-ADDomain).PDCEmulator
$currentDC = $env:COMPUTERNAME + "." + (Get-ADDomain).DNSRoot
Write-Host "    PDC Emulator: $pdc"
Write-Host "    Current DC:   $currentDC"

if ($currentDC -ne $pdc) {
    Write-Host "    [!] WARNING: Not running on PDC Emulator!" -ForegroundColor Red
    Write-Host "        Recommended: Run on $pdc" -ForegroundColor Yellow
} else {
    Write-Host "    [OK] Running on PDC Emulator" -ForegroundColor Green
}

$replStatus = repadmin /showrepl 2>&1
if ($replStatus -match "error|fail") {
    Write-Host "    [!] Replication issues detected - fix before rotating!" -ForegroundColor Red
} else {
    Write-Host "    [OK] Replication appears healthy" -ForegroundColor Green
}

# Step 2: Check krbtgt status
Write-Host "`n[STEP 2] Checking krbtgt account..." -ForegroundColor Yellow
$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
$daysSince = ((Get-Date) - $krbtgt.PasswordLastSet).Days

Write-Host "    Last Password Set: $($krbtgt.PasswordLastSet)"
Write-Host "    Days Since Rotation: $daysSince days" -ForegroundColor $(
    if ($daysSince -gt 180) {"Red"}
    elseif ($daysSince -gt 90) {"Yellow"}
    else {"Green"}
)

# Step 3: DC inventory
Write-Host "`n[STEP 3] Domain Controllers..." -ForegroundColor Yellow
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    Write-Host "    > $($dc.Name) ($($dc.IPv4Address))" -ForegroundColor Yellow
}
Write-Host "    Wait time after rotation: $($dcs.Count * 15) minutes minimum" -ForegroundColor Cyan

# Step 4: Rotate
Write-Host "`n[STEP 4] krbtgt Password Rotation..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "    [WHATIF] Would reset krbtgt password" -ForegroundColor Yellow
    Write-Host "    [WHATIF] Users may need to re-authenticate" -ForegroundColor Yellow
} else {
    Write-Host "    [!] ROTATING krbtgt password..." -ForegroundColor Red

    $before = Get-ADUser -Identity krbtgt -Properties PasswordLastSet

    $newPass = (New-Guid).ToString().Replace("-","") + "!Aa1"
    Set-ADAccountPassword -Identity krbtgt `
        -Reset `
        -NewPassword (ConvertTo-SecureString -AsPlainText $newPass -Force)

    $after = Get-ADUser -Identity krbtgt -Properties PasswordLastSet

    if ($after.PasswordLastSet -gt $before.PasswordLastSet) {
        Write-Host "    [OK] krbtgt rotated successfully ✅" -ForegroundColor Green
        Write-Host "    [OK] New PasswordLastSet: $($after.PasswordLastSet)" -ForegroundColor Green
    } else {
        Write-Host "    [!] Rotation may have failed - verify manually" -ForegroundColor Red
    }
}

# Step 5: Next steps
Write-Host "`n[STEP 5] Next Steps..." -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "    1. Set WhatIf = false and run" -ForegroundColor Cyan
    Write-Host "    2. Wait 10+ hours" -ForegroundColor Cyan
    Write-Host "    3. Run again for Rotation 2" -ForegroundColor Cyan
    Write-Host "    4. Monitor Event ID 4769 for Kerberos issues" -ForegroundColor Cyan
} else {
    Write-Host "    > Force replication: repadmin /syncall /AdeP" -ForegroundColor Cyan
    Write-Host "    > Wait 10+ hours" -ForegroundColor Yellow
    Write-Host "    > Run script again for Rotation 2" -ForegroundColor Yellow
    Write-Host "    > Monitor Event ID 4769 for Kerberos issues" -ForegroundColor Cyan
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# krbtgt signs ALL Kerberos tickets in the domain.
# If compromised > attacker can forge Golden Tickets.
# Golden Ticket = unlimited domain access for 10 years.
#
# Why rotate TWICE:
#   AD keeps PREVIOUS krbtgt password as backup.
#   Rotation 1: New password set, old still valid
#   Wait 10h:   DCs replicate, existing tickets expire
#   Rotation 2: Old backup replaced, Golden Tickets invalid
#
# Event IDs to monitor:
#   4769 = Kerberos ticket request (watch for failures)
#   4771 = Kerberos pre-authentication failed
#   14   = KDC error (System log)
#
# Impact: ⚠️ High - use maintenance window
#   Run on PDC Emulator for best results.
#   Verify replication health before rotating.
#
# Verification:
#   Get-ADUser krbtgt -Properties PasswordLastSet
#   Expected: PasswordLastSet = today
