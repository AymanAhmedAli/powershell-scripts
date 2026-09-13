# ================================
# fix_audit_policy.ps1
# Author: Ayman Ahmed
# Description: Enables advanced audit policy on Domain Controllers
#              Covers authentication, account management, directory events
# Usage: .\fixes\fix_audit_policy.ps1
# Requirements: PowerShell 5.1+, Domain Admin, Run on DC
# ================================

$WhatIf = $true  # Change to $false to apply fix

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Advanced Audit Policy" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$auditSettings = @(
    @{ Subcategory = "Credential Validation" }
    @{ Subcategory = "User Account Management" }
    @{ Subcategory = "Computer Account Management" }
    @{ Subcategory = "Security Group Management" }
    @{ Subcategory = "Logon" }
    @{ Subcategory = "Logoff" }
    @{ Subcategory = "Account Lockout" }
    @{ Subcategory = "Directory Service Access" }
    @{ Subcategory = "Directory Service Changes" }
    @{ Subcategory = "Audit Policy Change" }
    @{ Subcategory = "Sensitive Privilege Use" }
    @{ Subcategory = "Security System Extension" }
)

Write-Host "`n[*] Audit categories to configure:" -ForegroundColor Yellow
foreach ($setting in $auditSettings) {
    Write-Host "    → $($setting.Subcategory)"
}

if ($WhatIf) {
    Write-Host "`n[WHATIF] Would enable Success and Failure for all categories" -ForegroundColor Yellow
    Write-Host "         Change WhatIf to false to apply" -ForegroundColor Yellow
} else {
    Write-Host "`n[*] Applying audit policy..." -ForegroundColor Yellow
    foreach ($setting in $auditSettings) {
        auditpol /set /subcategory:"$($setting.Subcategory)" `
            /success:enable /failure:enable | Out-Null
        Write-Host "    [OK] $($setting.Subcategory)" -ForegroundColor Green
    }
    Write-Host "`n[OK] Advanced audit policy configured successfully ✅" -ForegroundColor Green
    Write-Host "     Verify with: auditpol /get /category:*" -ForegroundColor Cyan
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Defines list of critical audit subcategories
# 2. WhatIf=$true → shows what would be enabled
# 3. WhatIf=$false → uses auditpol.exe to enable Success+Failure
#
# Why this matters:
#   Without auditing, attacks go undetected:
#   → Failed logons not logged = brute force invisible
#   → Group changes not logged = privilege escalation invisible
#   → Directory changes not logged = AD modifications invisible
#
# Impact: ✅ Low — only increases log volume
#   Monitor disk space on DC after enabling.
#
# Verification:
#   auditpol /get /category:*
