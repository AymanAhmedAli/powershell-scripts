# ================================
# fix_protected_users.ps1
# Author: Ayman Ahmed
# Description: Adds admin accounts to Protected Users security group
#              Prevents credential theft and delegation attacks
# Usage: .\fixes\fix_protected_users.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# WARNING: Test on non-production accounts first
# ================================

$WhatIf = $true  # Change to $false to apply fix

$ExcludedAccounts = @("krbtgt", "Guest")

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Add Admins to Protected Users" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
$protectedNames = $protectedUsers.SamAccountName

Write-Host "`n[*] Current Protected Users members: $($protectedUsers.Count)" -ForegroundColor Yellow
foreach ($member in $protectedUsers) {
    Write-Host "    - $($member.SamAccountName)" -ForegroundColor Gray
}

$adminAccounts = Get-ADUser -Filter {AdminCount -eq 1} |
    Where-Object { $_.SamAccountName -notin $ExcludedAccounts }

Write-Host "`n[*] Admin accounts to protect: $($adminAccounts.Count)" -ForegroundColor Yellow

$added = 0
$alreadyIn = 0

foreach ($account in $adminAccounts) {
    if ($account.SamAccountName -in $protectedNames) {
        Write-Host "  [OK] $($account.SamAccountName) — already protected" -ForegroundColor Green
        $alreadyIn++
    } else {
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would add: $($account.SamAccountName)" -ForegroundColor Yellow
        } else {
            Add-ADGroupMember -Identity "Protected Users" -Members $account.SamAccountName
            Write-Host "  [OK] Added: $($account.SamAccountName) ✅" -ForegroundColor Green
            $added++
        }
    }
}

if (!$WhatIf) {
    $newMembers = Get-ADGroupMember -Identity "Protected Users"
    Write-Host "`n[*] Protected Users now has $($newMembers.Count) members" -ForegroundColor Yellow
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "  Admin Accounts Found: $($adminAccounts.Count)" -ForegroundColor Yellow
if ($WhatIf) {
    $toAdd = ($adminAccounts | Where-Object { $_.SamAccountName -notin $protectedNames }).Count
    Write-Host "  Would Add: $toAdd" -ForegroundColor Yellow
} else {
    Write-Host "  Already Protected: $alreadyIn" -ForegroundColor Green
    Write-Host "  Newly Added:       $added" -ForegroundColor Green
}
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Lists current Protected Users members
# 2. Gets all accounts with AdminCount=1
# 3. WhatIf=$true → shows what would be added
# 4. WhatIf=$false → adds accounts and verifies
#
# Why this matters:
#   Protected Users group enforces:
#   → No NTLM authentication (prevents pass-the-hash)
#   → No DES or RC4 encryption (only AES)
#   → No unconstrained delegation
#   → TGT lifetime limited to 4 hours
#
# WARNING: Legacy apps using NTLM or RC4 may break.
#   Test with non-critical accounts first.
#   Do NOT add service accounts.
#
# Impact: ⚠️ Medium — test legacy apps first
#
# Verification:
#   Get-ADGroupMember -Identity "Protected Users"

