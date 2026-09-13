# ================================
# ad_health_check.ps1
# Author: Ayman Ahmed
# Description: Quick AD Health Check Report
# Usage: .\ad_health_check.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

$Domain = $env:USERDNSDOMAIN

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  AD Health Check Report" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "  Domain: $Domain" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ===== Domain Info =====
Write-Host "`n[*] Domain Information" -ForegroundColor Yellow
$domain = Get-ADDomain
Write-Host "    Domain: $($domain.DNSRoot)"
Write-Host "    PDC: $($domain.PDCEmulator)"
Write-Host "    Forest: $($domain.Forest)"

# ===== Domain Controllers =====
Write-Host "`n[*] Domain Controllers" -ForegroundColor Yellow
Get-ADDomainController -Filter * | ForEach-Object {
    Write-Host "    $($_.Name) - $($_.IPv4Address) - $($_.OperatingSystem)"
}

# ===== Users Stats =====
Write-Host "`n[*] Users Statistics" -ForegroundColor Yellow
$allUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires
$enabled        = ($allUsers | Where-Object {$_.Enabled -eq $true}).Count
$disabled       = ($allUsers | Where-Object {$_.Enabled -eq $false}).Count
$neverExpires   = ($allUsers | Where-Object {$_.PasswordNeverExpires -eq $true}).Count
$inactive       = ($allUsers | Where-Object {
    $_.Enabled -eq $true -and
    $_.LastLogonDate -lt (Get-Date).AddDays(-90) -and
    $_.LastLogonDate -ne $null
}).Count

Write-Host "    Total Users:              $($allUsers.Count)"
Write-Host "    Enabled:                  $enabled"
Write-Host "    Disabled:                 $disabled"
Write-Host "    Password Never Expires:   $neverExpires" -ForegroundColor $(if($neverExpires -gt 0){"Red"}else{"Green"})
Write-Host "    Inactive (90+ days):      $inactive" -ForegroundColor $(if($inactive -gt 0){"Red"}else{"Green"})

# ===== Privileged Groups =====
Write-Host "`n[*] Privileged Groups" -ForegroundColor Yellow
$groups = @("Domain Admins","Schema Admins","Enterprise Admins","Administrators")
foreach ($group in $groups) {
    $members = Get-ADGroupMember -Identity $group -Recursive
    Write-Host "    $group`: $($members.Count) members"
    $members | ForEach-Object {
        $color = if ($group -eq "Schema Admins" -and $_.SamAccountName -ne "Administrator") {"Red"} else {"White"}
        Write-Host "      - $($_.SamAccountName)" -ForegroundColor $color
    }
}

# ===== Password Policy =====
Write-Host "`n[*] Default Password Policy" -ForegroundColor Yellow
$policy = Get-ADDefaultDomainPasswordPolicy
Write-Host "    Min Length:      $($policy.MinPasswordLength)" -ForegroundColor $(if($policy.MinPasswordLength -lt 12){"Red"}else{"Green"})
Write-Host "    Max Age:         $($policy.MaxPasswordAge.Days) days"
Write-Host "    Complexity:      $($policy.ComplexityEnabled)"
Write-Host "    Lockout After:   $($policy.LockoutThreshold) attempts" -ForegroundColor $(if($policy.LockoutThreshold -eq 0){"Red"}else{"Green"})

# ===== Security Checks =====
Write-Host "`n[*] Security Checks" -ForegroundColor Yellow
$quota = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
if ($quota -gt 0) {
    Write-Host "    [!] Machine Account Quota: $quota (should be 0)" -ForegroundColor Red
} else {
    Write-Host "    [OK] Machine Account Quota: $quota" -ForegroundColor Green
}

$schemaAdmins = Get-ADGroupMember -Identity "Schema Admins"
if ($schemaAdmins.Count -gt 0) {
    Write-Host "    [!] Schema Admins has $($schemaAdmins.Count) members (should be empty)" -ForegroundColor Red
} else {
    Write-Host "    [OK] Schema Admins is empty" -ForegroundColor Green
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Report Complete" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# Generates a quick health report of the Active Directory environment.
# Covers: Domain info, DCs, users stats, privileged groups,
#         password policy, and basic security checks.
# READ-ONLY — makes no changes to the environment.
