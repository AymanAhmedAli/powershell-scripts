# ================================
# fix_password_policy.ps1
# Author: Ayman Ahmed
# Description: Enforces stronger password policy
#              Min length 12+, lockout after 5 attempts
# Usage: .\fixes\fix_password_policy.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# WARNING: Announce to users before applying in production
# ================================

$WhatIf = $true  # Change to $false to apply fix

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Password Policy" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$policy = Get-ADDefaultDomainPasswordPolicy

Write-Host "`n[*] Current Policy:" -ForegroundColor Yellow
Write-Host "    Min Length:       $($policy.MinPasswordLength)"
Write-Host "    Max Age:          $($policy.MaxPasswordAge.Days) days"
Write-Host "    Lockout After:    $($policy.LockoutThreshold) attempts"
Write-Host "    Lockout Duration: $($policy.LockoutDuration.Minutes) minutes"
Write-Host "    Complexity:       $($policy.ComplexityEnabled)"

Write-Host "`n[*] Target Policy:" -ForegroundColor Cyan
Write-Host "    Min Length:       12"
Write-Host "    Max Age:          90 days"
Write-Host "    Lockout After:    5 attempts"
Write-Host "    Lockout Duration: 30 minutes"
Write-Host "    Complexity:       True"
Write-Host "    History:          24 passwords"

if ($WhatIf) {
    Write-Host "`n[WHATIF] Would update password policy" -ForegroundColor Yellow
    Write-Host "         Change WhatIf to false to apply" -ForegroundColor Yellow
} else {
    Write-Host "`n[*] Applying password policy..." -ForegroundColor Yellow

    Set-ADDefaultDomainPasswordPolicy `
        -Identity (Get-ADDomain).DNSRoot `
        -MinPasswordLength 12 `
        -MaxPasswordAge "90.00:00:00" `
        -LockoutThreshold 5 `
        -LockoutDuration "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -ComplexityEnabled $true `
        -PasswordHistoryCount 24

    $newPolicy = Get-ADDefaultDomainPasswordPolicy
    Write-Host "`n[*] New Policy:" -ForegroundColor Green
    Write-Host "    Min Length:    $($newPolicy.MinPasswordLength)"
    Write-Host "    Max Age:       $($newPolicy.MaxPasswordAge.Days) days"
    Write-Host "    Lockout After: $($newPolicy.LockoutThreshold) attempts"
    Write-Host "    Complexity:    $($newPolicy.ComplexityEnabled)"

    if ($newPolicy.MinPasswordLength -ge 12 -and $newPolicy.LockoutThreshold -gt 0) {
        Write-Host "`n[OK] Password policy updated successfully ✅" -ForegroundColor Green
    } else {
        Write-Host "`n[!] Failed to apply policy" -ForegroundColor Red
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Shows current vs target password policy
# 2. WhatIf=$true → shows what would change
# 3. WhatIf=$false → applies new policy and verifies
#
# Why this matters:
#   Short passwords are brute-forced quickly:
#   → 7 chars = crackable in minutes with modern GPUs
#   → 12 chars = significantly harder
#   Account lockout prevents brute force attacks.
#
# WARNING: Announce to users before applying.
#   Users with short passwords must change at next login.
#
# Impact: ⚠️ Medium — announce to users first
#
# Verification:
#   Get-ADDefaultDomainPasswordPolicy
