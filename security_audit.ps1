# ================================
# security_audit.ps1
# Author: Ayman Ahmed
# Description: Comprehensive AD security audit based on pentest findings
#              Covers Critical, High, and Medium severity findings
# Usage: .\security_audit.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# Note: READ-ONLY — makes no changes to the environment
# ================================

$LogFile = "C:\Logs\security_audit_$(Get-Date -Format 'yyyyMMdd_HHmm').log"
if (!(Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" | Out-Null }

$Critical = 0
$High = 0
$Medium = 0
$Passed = 0

function Write-Log {
    param($Message, $Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $log = "[$timestamp] $Message"
    Write-Host $log -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $log
}

function Check-Finding {
    param($ID, $Severity, $Description, $Status, $Detail, $Remediation)
    if ($Status) {
        Write-Log "  [OK] [$Severity] $ID — $Description" "Green"
        Write-Log "       $Detail" "Gray"
        $script:Passed++
    } else {
        $color = switch ($Severity) {
            "Critical" { "Red" }
            "High"     { "Magenta" }
            "Medium"   { "Yellow" }
        }
        Write-Log "  [!] [$Severity] $ID — $Description" $color
        Write-Log "       Found: $Detail" "Yellow"
        Write-Log "       Fix: $Remediation" "Cyan"
        switch ($Severity) {
            "Critical" { $script:Critical++ }
            "High"     { $script:High++ }
            "Medium"   { $script:Medium++ }
        }
    }
}

Write-Log "=================================================" "Cyan"
Write-Log "  AD Security Audit Report" "Cyan"
Write-Log "  Domain: $env:USERDNSDOMAIN" "Cyan"
Write-Log "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" "Cyan"
Write-Log "=================================================" "Cyan"

# ===== CRITICAL =====
Write-Log "`n===== CRITICAL FINDINGS =====" "Red"

# Machine Account Quota
Write-Log "`n[*] S-ADRegistration" "Yellow"
$quota = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName `
    -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
Check-Finding "S-ADRegistration" "Critical" `
    "Non-admin users can add computers to domain" `
    ($quota -eq 0) `
    "Machine Account Quota: $quota" `
    'Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"}'

# Schema Admins
Write-Log "`n[*] P-SchemaAdmin" "Yellow"
$schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -ErrorAction SilentlyContinue
Check-Finding "P-SchemaAdmin" "Critical" `
    "Schema Admins contains accounts" `
    ($schemaAdmins.Count -eq 0) `
    "Members: $($schemaAdmins.SamAccountName -join ', ') ($($schemaAdmins.Count) accounts)" `
    "Remove all members — grant temporary access only when needed"

# Password Length
Write-Log "`n[*] A-MinPwdLen" "Yellow"
$policy = Get-ADDefaultDomainPasswordPolicy
Check-Finding "A-MinPwdLen" "Critical" `
    "Password policy permits short passwords" `
    ($policy.MinPasswordLength -ge 8) `
    "Min Length: $($policy.MinPasswordLength)" `
    "Set minimum password length to 12+"

# AD Recycle Bin
Write-Log "`n[*] P-RecycleBin" "Yellow"
$recycleBin = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}
Check-Finding "P-RecycleBin" "Critical" `
    "AD Recycle Bin is not enabled" `
    ($recycleBin.EnabledScopes.Count -gt 0) `
    "Enabled: False" `
    "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target `$env:USERDNSDOMAIN"

# Domain Admins with non-expiring passwords
Write-Log "`n[*] P-ServiceDomainAdmin" "Yellow"
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Get-ADUser -Properties PasswordNeverExpires |
    Where-Object { $_.PasswordNeverExpires -eq $true }
Check-Finding "P-ServiceDomainAdmin" "Critical" `
    "Domain Admins with non-expiring passwords" `
    ($domainAdmins.Count -eq 0) `
    "Accounts: $($domainAdmins.SamAccountName -join ', ') ($($domainAdmins.Count) accounts)" `
    "Remove service accounts from Domain Admins — use gMSA instead"

# Print Spooler on DCs
Write-Log "`n[*] A-DC-Spooler" "Yellow"
$dcs = Get-ADDomainController -Filter *
$spoolerRunning = @()
foreach ($dc in $dcs) {
    try {
        $spooler = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            Get-Service -Name Spooler
        } -ErrorAction Stop
        if ($spooler.Status -eq "Running") { $spoolerRunning += $dc.Name }
    } catch {}
}
Check-Finding "A-DC-Spooler" "Critical" `
    "Print Spooler running on Domain Controllers" `
    ($spoolerRunning.Count -eq 0) `
    "DCs with Spooler running: $($spoolerRunning -join ', ')" `
    "Disable via GPO: Computer Config → Preferences → Services → Spooler → Disabled"

# Protected Users
Write-Log "`n[*] P-ProtectedUsers" "Yellow"
$adminAccounts = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object { $_.objectClass -eq "user" }
$protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
$protectedNames = $protectedUsers.SamAccountName
$notProtected = $adminAccounts | Where-Object { $_.SamAccountName -notin $protectedNames }
Check-Finding "P-ProtectedUsers" "Critical" `
    "Admin accounts not in Protected Users group" `
    ($notProtected.Count -eq 0) `
    "Not protected: $($notProtected.SamAccountName -join ', ') ($($notProtected.Count) accounts)" `
    "Add admin accounts to Protected Users group after compatibility testing"

# Delegation
Write-Log "`n[*] P-Delegated" "Yellow"
$notDelegated = Get-ADUser -Filter { AdminCount -eq 1 } `
    -Properties AccountNotDelegated |
    Where-Object { $_.AccountNotDelegated -ne $true }
Check-Finding "P-Delegated" "Critical" `
    "Admin accounts not flagged sensitive/cannot be delegated" `
    ($notDelegated.Count -eq 0) `
    "Accounts not flagged: $($notDelegated.Count)" `
    "Set-ADUser -AccountNotDelegated `$true for all admin accounts"

# Backup
Write-Log "`n[*] A-BackupMetadata" "Yellow"
Write-Log "  [?] A-BackupMetadata — Run 'repadmin /showbackup *' to check manually" "Yellow"
Write-Log "       Recommended: Daily DC backup with tested restore" "Cyan"

# NTLM
Write-Log "`n[*] S-OldNtlm" "Yellow"
try {
    $ntlmLevel = (Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" -ErrorAction Stop).LmCompatibilityLevel
    Check-Finding "S-OldNtlm" "Critical" `
        "NTLM authentication level" `
        ($ntlmLevel -ge 5) `
        "LmCompatibilityLevel: $ntlmLevel (5=NTLMv2 only)" `
        "Set LmCompatibilityLevel to 5 after auditing NTLM usage"
} catch {
    Write-Log "  [?] S-OldNtlm — Check LmCompatibilityLevel registry manually" "Yellow"
}

# ===== HIGH =====
Write-Log "`n===== HIGH FINDINGS =====" "Magenta"

# Audit Policy
Write-Log "`n[*] A-AuditDC" "Yellow"
try {
    $auditResult = auditpol /get /category:"Logon/Logoff" 2>&1
    $logonAudit = $auditResult | Select-String "Logon" | Select-Object -First 1
    Check-Finding "A-AuditDC" "High" `
        "Advanced audit policy for authentication events" `
        ($logonAudit -match "Success and Failure") `
        "Current: $logonAudit" `
        "Configure via GPO: Advanced Audit Policy → Logon/Logoff → Success and Failure"
} catch {
    Write-Log "  [?] A-AuditDC — Run 'auditpol /get /category:*' to verify" "Yellow"
}

# ===== MEDIUM =====
Write-Log "`n===== MEDIUM FINDINGS =====" "Yellow"

# LDAP Signing
Write-Log "`n[*] A-DCLdapSign" "Yellow"
try {
    $ldapSigning = (Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity
    Check-Finding "A-DCLdapSign" "Medium" `
        "LDAP signing enforcement" `
        ($ldapSigning -eq 2) `
        "LDAPServerIntegrity: $ldapSigning (2=Required)" `
        "GPO: Domain controller: LDAP server signing requirements = Require signing"
} catch {
    Write-Log "  [?] A-DCLdapSign — Set via GPO: LDAP signing = Require" "Yellow"
}

# DC Subnets
Write-Log "`n[*] S-DC-SubnetMissing" "Yellow"
$dcIPs = (Get-ADDomainController -Filter *).IPv4Address
$subnets = Get-ADReplicationSubnet -Filter * -Properties Name
$uncoveredDCs = @()
foreach ($ip in $dcIPs) {
    $covered = $false
    foreach ($subnet in $subnets) {
        $network = $subnet.Name.Split("/")[0]
        if ($ip -like "$($network.Split(".")[0]).$($network.Split(".")[1]).*") {
            $covered = $true
        }
    }
    if (!$covered) { $uncoveredDCs += $ip }
}
Check-Finding "S-DC-SubnetMissing" "Medium" `
    "DC IPs not covered by AD subnets" `
    ($uncoveredDCs.Count -eq 0) `
    "Uncovered DC IPs: $($uncoveredDCs -join ', ')" `
    "Add subnets in AD Sites and Services for all DC IP ranges"

# Unsupported Windows
Write-Log "`n[*] S-OS-W10" "Yellow"
$unsupported = Get-ADComputer -Filter {Enabled -eq $true} -Properties OperatingSystem |
    Where-Object { $_.OperatingSystem -match "Windows 10" -and
                   $_.OperatingSystem -notmatch "Enterprise|Education" }
Check-Finding "S-OS-W10" "Medium" `
    "Unsupported Windows editions" `
    ($unsupported.Count -eq 0) `
    "Unsupported: $($unsupported.Name -join ', ') ($($unsupported.Count) computers)" `
    "Upgrade to supported Windows editions or retire affected machines"

# ===== SUMMARY =====
$Total = $Critical + $High + $Medium
Write-Log "`n=================================================" "Cyan"
Write-Log "  AUDIT SUMMARY" "Cyan"
Write-Log "=================================================" "Cyan"
Write-Log "  Critical Issues : $Critical" "Red"
Write-Log "  High Issues     : $High" "Magenta"
Write-Log "  Medium Issues   : $Medium" "Yellow"
Write-Log "  Passed Checks   : $Passed" "Green"
Write-Log "  Total Issues    : $Total" $(if($Total -gt 5){"Red"}else{"Yellow"})
Write-Log "  Log saved       : $LogFile" "Cyan"
Write-Log "=================================================" "Cyan"

if ($Total -eq 0) {
    Write-Log "  Result: All checks passed! ✅" "Green"
} elseif ($Critical -gt 0) {
    Write-Log "  Result: CRITICAL issues require immediate attention!" "Red"
} else {
    Write-Log "  Result: Review and remediate findings above" "Yellow"
}
Write-Log "=================================================" "Cyan"

# ================================
# How it works:
# ================================
# Performs comprehensive AD security audit based on pentest findings.
# Covers: Critical, High, and Medium severity checks.
# READ-ONLY — makes no changes to the environment.
# Each finding includes ID, severity, detail, and remediation steps.
# Results saved to C:\Logs\ with timestamp.
