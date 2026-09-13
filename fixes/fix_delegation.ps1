# ================================
# fix_delegation.ps1
# Author: Ayman Ahmed
# Description: Flags admin accounts as sensitive and cannot be delegated
#              Prevents Kerberos delegation attacks on privileged accounts
# Usage: .\fixes\fix_delegation.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

$WhatIf = $true  # Change to $false to apply fix

$ExcludedAccounts = @("krbtgt")

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Sensitive Delegation Flag" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$adminAccounts = Get-ADUser -Filter {AdminCount -eq 1} `
    -Properties AccountNotDelegated |
    Where-Object { $_.SamAccountName -notin $ExcludedAccounts }

Write-Host "`n[*] Found $($adminAccounts.Count) admin accounts" -ForegroundColor Yellow

$fixed = 0
$alreadySet = 0

foreach ($account in $adminAccounts) {
    if ($account.AccountNotDelegated -eq $true) {
        Write-Host "  [OK] $($account.SamAccountName) — already flagged" -ForegroundColor Green
        $alreadySet++
    } else {
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would flag: $($account.SamAccountName)" -ForegroundColor Yellow
        } else {
            Set-ADUser -Identity $account.SamAccountName -AccountNotDelegated $true
            Write-Host "  [OK] Flagged: $($account.SamAccountName) ✅" -ForegroundColor Green
            $fixed++
        }
    }
}

if (!$WhatIf) {
    $notFixed = Get-ADUser -Filter {AdminCount -eq 1} `
        -Properties AccountNotDelegated |
        Where-Object {
            $_.AccountNotDelegated -ne $true -and
            $_.SamAccountName -notin $ExcludedAccounts
        }
    if ($notFixed.Count -eq 0) {
        Write-Host "`n[OK] All admin accounts flagged successfully ✅" -ForegroundColor Green
    } else {
        Write-Host "`n[!] $($notFixed.Count) accounts still not flagged" -ForegroundColor Red
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "  Total Admin Accounts: $($adminAccounts.Count)" -ForegroundColor Yellow
if ($WhatIf) {
    $toFlag = ($adminAccounts | Where-Object {$_.AccountNotDelegated -ne $true}).Count
    Write-Host "  Would Flag: $toFlag" -ForegroundColor Yellow
} else {
    Write-Host "  Already Flagged: $alreadySet" -ForegroundColor Green
    Write-Host "  Newly Flagged:   $fixed" -ForegroundColor Green
}
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Gets all accounts with AdminCount=1
# 2. Checks if AccountNotDelegated flag is set
# 3. WhatIf=$true → shows what would be changed
# 4. WhatIf=$false → sets flag and verifies
#
# Why this matters:
#   If admin account is delegatable:
#   → Attacker compromises a service with delegation rights
#   → Service can impersonate the admin account
#   → Full domain compromise possible
#
# Impact: ✅ Zero — safe to apply immediately
#
# Verification:
#   Get-ADUser -Filter {AdminCount -eq 1} -Properties AccountNotDelegated |
#   Select SamAccountName, AccountNotDelegated
#   Expected: AccountNotDelegated = True for all
