# ================================
# fix_ldap_signing.ps1
# Author: Ayman Ahmed
# Description: Enforces LDAP signing and channel binding on DCs
#              Prevents LDAP relay and MITM attacks
# Usage: .\fixes\fix_ldap_signing.ps1
# Requirements: PowerShell 5.1+, Domain Admin, Run on DC
#
# IMPORTANT - 3 Phase approach:
#   Phase 1: Audit  - enable logging only (zero impact)
#   Phase 2: Negotiate - request but don't require (low impact)
#   Phase 3: Require - full enforcement (potential impact)
#
#   Start Phase 1, wait 2 weeks, check Event ID 2889,
#   then move to Phase 3 if no unsigned binds detected.
# ================================

$WhatIf = $true  # Change to $false to apply
$Phase   = 1     # 1=Audit, 2=Negotiate, 3=Require

$PhaseNames = @{
    1 = "Audit (log unsigned LDAP)"
    2 = "Negotiate (request but don't require)"
    3 = "Require signing (full enforcement)"
}

$LDAPValues = @{ 1 = 0; 2 = 1; 3 = 2 }

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: LDAP Signing Enforcement" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  Phase: $Phase - $($PhaseNames[$Phase])" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

# Step 1: Check current state
Write-Host "`n[STEP 1] Current LDAP signing configuration..." -ForegroundColor Yellow
try {
    $currentValue = (Get-ItemProperty -Path $regPath `
        -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity
    $currentName = switch ($currentValue) {
        0 { "None" }; 1 { "Negotiate" }; 2 { "Required" }
        default { "Unknown ($currentValue)" }
    }
    Write-Host "    Current: $currentValue - $currentName" -ForegroundColor $(
        if ($currentValue -eq 2) {"Green"}
        elseif ($currentValue -eq 1) {"Yellow"}
        else {"Red"}
    )
} catch {
    Write-Host "    LDAPServerIntegrity not set (default = Negotiate)" -ForegroundColor Yellow
    $currentValue = 1
}

# Step 2: Enable audit events
Write-Host "`n[STEP 2] LDAP audit events..." -ForegroundColor Yellow
$auditPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
if ($WhatIf) {
    Write-Host "    [WHATIF] Would set LDAP audit level to 2 (Basic)" -ForegroundColor Yellow
} else {
    Set-ItemProperty -Path $auditPath -Name "16 LDAP Interface Events" -Value 2 -Type DWord
    Write-Host "    [OK] LDAP audit events enabled (Level 2)" -ForegroundColor Green
    Write-Host "    Monitor Event ID 2889 for unsigned binds" -ForegroundColor Cyan
}

# Step 3: Apply signing requirement
Write-Host "`n[STEP 3] Applying Phase $Phase..." -ForegroundColor Yellow
$targetValue = $LDAPValues[$Phase]

if ($currentValue -eq $targetValue) {
    Write-Host "    [OK] Already at Phase $Phase" -ForegroundColor Green
} else {
    if ($WhatIf) {
        Write-Host "    [WHATIF] Would set LDAPServerIntegrity: $currentValue > $targetValue" -ForegroundColor Yellow
    } else {
        Set-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -Value $targetValue -Type DWord
        Write-Host "    [OK] LDAPServerIntegrity set to $targetValue ✅" -ForegroundColor Green
    }
}

# Step 4: Channel Binding (Phase 3 only)
if ($Phase -eq 3) {
    Write-Host "`n[STEP 4] Enabling LDAP Channel Binding..." -ForegroundColor Yellow
    if ($WhatIf) {
        Write-Host "    [WHATIF] Would set LdapEnforceChannelBinding to 2 (Always)" -ForegroundColor Yellow
    } else {
        Set-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
        Write-Host "    [OK] Channel Binding set to Always ✅" -ForegroundColor Green
    }
} else {
    Write-Host "`n[STEP 4] Channel Binding - skipped (Phase 3 only)" -ForegroundColor Gray
}

# Step 5: Next steps
Write-Host "`n[STEP 5] Next Steps..." -ForegroundColor Yellow
switch ($Phase) {
    1 {
        Write-Host "    > Wait 2 weeks" -ForegroundColor Cyan
        Write-Host "    > Check Event ID 2889 in Directory Service log" -ForegroundColor Cyan
        Write-Host "    > If no Event 2889 > move to Phase 3" -ForegroundColor Cyan
        Write-Host "    > If Event 2889 exists > fix those apps first" -ForegroundColor Red
    }
    2 {
        Write-Host "    > Monitor for LDAP client issues" -ForegroundColor Cyan
        Write-Host "    > Check Event ID 2889" -ForegroundColor Cyan
        Write-Host "    > When stable > move to Phase 3" -ForegroundColor Cyan
    }
    3 {
        Write-Host "    > LDAP signing fully enforced ✅" -ForegroundColor Green
        Write-Host "    > Monitor Event ID 2888 for rejected unsigned binds" -ForegroundColor Cyan
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done - Phase $Phase Complete" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# WITHOUT signing: attacker can read/modify LDAP traffic (MITM)
# WITH signing: every LDAP message is cryptographically signed
#
# Registry Keys:
#   LDAPServerIntegrity: 0=None, 1=Negotiate, 2=Required
#   LdapEnforceChannelBinding: 0=Never, 1=Supported, 2=Always
#
# Event IDs:
#   2889 = unsigned LDAP bind detected (WARNING)
#   2888 = unsigned bind rejected (INFO)
#
# Impact: ⚠️ High - use 3-phase approach
#   Legacy apps using unsigned LDAP will break in Phase 3.
#   Always run Phase 1 audit first for 2 weeks.
#
# Verification:
#   Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
#   LDAPServerIntegrity should be 2
#   LdapEnforceChannelBinding should be 2
