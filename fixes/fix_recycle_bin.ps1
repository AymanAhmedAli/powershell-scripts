# ================================
# fix_recycle_bin.ps1
# Author: Ayman Ahmed
# Description: Enables Active Directory Recycle Bin
#              Allows recovery of accidentally deleted AD objects
# Usage: .\fixes\fix_recycle_bin.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# WARNING: IRREVERSIBLE - cannot be undone after enabling
# ================================

$WhatIf = $true  # Change to $false to apply fix

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: AD Recycle Bin" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$recycleBin = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}
$isEnabled = $recycleBin.EnabledScopes.Count -gt 0

Write-Host "`n[*] Current Status: $(if($isEnabled){'Enabled'}else{'Disabled'})" -ForegroundColor Yellow

if ($isEnabled) {
    Write-Host "[OK] AD Recycle Bin already enabled" -ForegroundColor Green
} else {
    if ($WhatIf) {
        Write-Host "[WHATIF] Would enable AD Recycle Bin" -ForegroundColor Yellow
        Write-Host "         WARNING: This change is IRREVERSIBLE" -ForegroundColor Red
        Write-Host "         Change WhatIf to false to apply" -ForegroundColor Yellow
    } else {
        Write-Host "`n[!] WARNING: This change cannot be undone!" -ForegroundColor Red
        Write-Host "[*] Enabling AD Recycle Bin..." -ForegroundColor Yellow

        Enable-ADOptionalFeature 'Recycle Bin Feature' `
            -Scope ForestOrConfigurationSet `
            -Target (Get-ADDomain).Forest `
            -Confirm:$false

        $verify = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}
        if ($verify.EnabledScopes.Count -gt 0) {
            Write-Host "[OK] AD Recycle Bin enabled successfully ✅" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to enable" -ForegroundColor Red
        }
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Checks if Recycle Bin Feature is enabled
# 2. WhatIf=$true > shows what would happen with irreversible warning
# 3. WhatIf=$false > enables at forest level and verifies
#
# Why this matters:
#   Without AD Recycle Bin, deleted objects are permanently gone.
#   With it: deleted objects retained 180 days, full restore possible.
#   Restore command: Restore-ADObject -Identity <object>
#
# WARNING: IRREVERSIBLE - cannot be disabled after enabling.
#
# Impact: Positive only ✅ - safe to apply immediately
#
# Verification:
#   (Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}).EnabledScopes
#   Expected: non-empty list
