# ================================
# dc_security_check.ps1
# Author: Ayman Ahmed
# Description: Checks DC security misconfigurations
# Usage: .\dc_security_check.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  DC Security Check Report" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$issues = 0

function Check-Item {
    param($Name, $Status, $Detail, $Expected)
    if ($Status) {
        Write-Host "  [OK] $Name" -ForegroundColor Green
        Write-Host "       $Detail" -ForegroundColor Gray
    } else {
        Write-Host "  [!] $Name" -ForegroundColor Red
        Write-Host "       Found: $Detail" -ForegroundColor Yellow
        Write-Host "       Expected: $Expected" -ForegroundColor Cyan
        $script:issues++
    }
}

# Machine Account Quota
Write-Host "`n[*] Checking Machine Account Quota..." -ForegroundColor Yellow
$quota = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName `
    -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
Check-Item "Machine Account Quota" ($quota -eq 0) "Value: $quota" "0"

# Schema Admins
Write-Host "`n[*] Checking Schema Admins..." -ForegroundColor Yellow
$schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -ErrorAction SilentlyContinue
Check-Item "Schema Admins Empty" ($schemaAdmins.Count -eq 0) `
    "Members: $($schemaAdmins.SamAccountName -join ', ')" "Empty group"

# Password Policy
Write-Host "`n[*] Checking Password Policy..." -ForegroundColor Yellow
$policy = Get-ADDefaultDomainPasswordPolicy
Check-Item "Min Password Length" ($policy.MinPasswordLength -ge 12) `
    "Length: $($policy.MinPasswordLength)" "12+"
Check-Item "Account Lockout" ($policy.LockoutThreshold -gt 0) `
    "Threshold: $($policy.LockoutThreshold)" "5-10 attempts"
Check-Item "Password Complexity" ($policy.ComplexityEnabled) `
    "Enabled: $($policy.ComplexityEnabled)" "True"

# Password Never Expires
Write-Host "`n[*] Checking Password Never Expires..." -ForegroundColor Yellow
$neverExpires = Get-ADUser -Filter {
    PasswordNeverExpires -eq $true -and Enabled -eq $true
} -Properties PasswordNeverExpires |
Where-Object { $_.SamAccountName -ne "krbtgt" }
Check-Item "No Password Never Expires" ($neverExpires.Count -eq 0) `
    "Users: $($neverExpires.SamAccountName -join ', ')" "0 users"

# Print Spooler on DCs
Write-Host "`n[*] Checking Print Spooler on DCs..." -ForegroundColor Yellow
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    try {
        $spooler = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            Get-Service -Name Spooler
        } -ErrorAction Stop
        Check-Item "Print Spooler on $($dc.Name)" `
            ($spooler.Status -ne "Running") `
            "Status: $($spooler.Status)" "Stopped/Disabled"
    } catch {
        Write-Host "  [?] Cannot check spooler on $($dc.Name)" -ForegroundColor Gray
    }
}

# AD Recycle Bin
Write-Host "`n[*] Checking AD Recycle Bin..." -ForegroundColor Yellow
$recycleBin = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}
Check-Item "AD Recycle Bin Enabled" `
    ($recycleBin.EnabledScopes.Count -gt 0) `
    "Enabled: $($recycleBin.EnabledScopes.Count -gt 0)" "Enabled"

# Domain Admins Count
Write-Host "`n[*] Checking Privileged Groups..." -ForegroundColor Yellow
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins"
Check-Item "Domain Admins Count" ($domainAdmins.Count -le 3) `
    "Members: $($domainAdmins.Count)" "3 or fewer"

# LDAP Signing
Write-Host "`n[*] Checking LDAP Signing..." -ForegroundColor Yellow
try {
    $ldapSigning = (Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity
    Check-Item "LDAP Signing" ($ldapSigning -eq 2) `
        "Value: $ldapSigning (2=Required)" "2 (Required)"
} catch {
    Write-Host "  [?] LDAP Signing — check manually" -ForegroundColor Gray
}

# Summary
Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Security Check Complete" -ForegroundColor Cyan
if ($issues -eq 0) {
    Write-Host "  Result: All checks passed! ✅" -ForegroundColor Green
} else {
    Write-Host "  Issues Found: $issues" -ForegroundColor Red
    Write-Host "  Review findings above and remediate" -ForegroundColor Yellow
}
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# Performs targeted security checks on Domain Controllers.
# READ-ONLY — makes no changes to the environment.
# Checks: Machine Account Quota, Schema Admins, Password Policy,
#         Password Never Expires, Print Spooler, AD Recycle Bin,
#         Domain Admins count, LDAP Signing

