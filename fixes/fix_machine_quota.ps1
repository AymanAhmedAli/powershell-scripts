# ================================
# fix_machine_quota.ps1
# Author: Ayman Ahmed
# Description: Sets Machine Account Quota to 0
#              Prevents non-admin users from joining computers to domain
# Usage: .\fixes\fix_machine_quota.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

$WhatIf = $true  # Change to $false to apply fix

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Machine Account Quota" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$quota = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName `
    -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"

Write-Host "`n[*] Current Value: $quota" -ForegroundColor Yellow

if ($quota -eq 0) {
    Write-Host "[OK] Already set to 0 — no action needed" -ForegroundColor Green
} else {
    if ($WhatIf) {
        Write-Host "[WHATIF] Would set Machine Account Quota to 0" -ForegroundColor Yellow
        Write-Host "         Change WhatIf to false to apply" -ForegroundColor Yellow
    } else {
        Set-ADDomain -Identity (Get-ADDomain).DNSRoot `
            -Replace @{"ms-DS-MachineAccountQuota"="0"}

        $newQuota = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName `
            -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"

        if ($newQuota -eq 0) {
            Write-Host "[OK] Successfully set to 0 ✅" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to apply fix" -ForegroundColor Red
        }
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Reads current ms-DS-MachineAccountQuota from domain root
# 2. WhatIf=$true → shows what would happen
# 3. WhatIf=$false → sets quota to 0 and verifies
#
# Why this matters:
#   Default value is 10 — any domain user can join 10 computers.
#   Attackers use this for NTLM relay and Kerberoasting attacks.
#   Setting to 0 means only admins can join computers.
#
# Impact: Zero ✅ — safe to apply immediately
#
# Verification:
#   (Get-ADObject -Identity (Get-ADDomain).DistinguishedName
#    -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
#   Expected: 0
