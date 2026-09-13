# ================================
# fix_schema_admins.ps1
# Author: Ayman Ahmed
# Description: Removes all members from Schema Admins group
#              Schema Admins should be empty during normal operations
# Usage: .\fixes\fix_schema_admins.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

$WhatIf = $true  # Change to $false to apply fix

# Accounts to keep (never remove)
$KeepAccounts = @("Administrator")

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Schema Admins Cleanup" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$members = Get-ADGroupMember -Identity "Schema Admins"

Write-Host "`n[*] Current Members: $($members.Count)" -ForegroundColor Yellow
foreach ($member in $members) {
    Write-Host "    - $($member.SamAccountName)" -ForegroundColor Yellow
}

$toRemove = $members | Where-Object {
    $_.SamAccountName -notin $KeepAccounts
}

if ($members.Count -eq 0) {
    Write-Host "`n[OK] Schema Admins is already empty" -ForegroundColor Green
} elseif ($toRemove.Count -eq 0) {
    Write-Host "`n[OK] No non-essential members found" -ForegroundColor Green
} else {
    foreach ($member in $toRemove) {
        if ($WhatIf) {
            Write-Host "`n[WHATIF] Would remove: $($member.SamAccountName)" -ForegroundColor Yellow
        } else {
            Remove-ADGroupMember -Identity "Schema Admins" `
                -Members $member.SamAccountName -Confirm:$false
            Write-Host "`n[OK] Removed: $($member.SamAccountName) ✅" -ForegroundColor Green
        }
    }
}

if (!$WhatIf) {
    $remaining = Get-ADGroupMember -Identity "Schema Admins"
    Write-Host "`n[*] Remaining Members: $($remaining.Count)" -ForegroundColor Yellow
    if ($remaining.Count -eq 0) {
        Write-Host "[OK] Schema Admins is now empty ✅" -ForegroundColor Green
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Lists all current Schema Admins members
# 2. Identifies members not in KeepAccounts safelist
# 3. WhatIf=$true → shows what would be removed
# 4. WhatIf=$false → removes members and verifies
#
# Why this matters:
#   Schema Admins can modify the entire AD forest schema.
#   Compromised Schema Admin = full forest takeover.
#   Best practice: Keep Schema Admins EMPTY.
#   Add members temporarily only when schema changes are needed.
#
# Impact: Zero ✅ — safe to apply immediately
#
# Verification:
#   Get-ADGroupMember -Identity "Schema Admins"
#   Expected: empty
