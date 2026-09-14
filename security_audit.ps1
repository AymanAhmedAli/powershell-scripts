# security_audit.ps1
# Author: Ayman Ahmed
# READ-ONLY - no changes made

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
        Write-Log "  [OK] [$Severity] $ID - $Description" "Green"
        Write-Log "       $Detail" "Gray"
        $script:Passed++
    } else {
        $color = switch ($Severity) {
            "Critical" { "Red" }
            "High"     { "Magenta" }
            "Medium"   { "Yellow" }
        }
        Write-Log "  [!] [$Severity] $ID - $Description" $color
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

Write-Log "`n===== CRITICAL FINDINGS =====" "Red"

Write-Log "`n[*] S-ADRegistration" "Yellow"
$quota = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
Check-Finding "S-ADRegistration" "Critical" "Non-admin users can add computers to domain" ($quota -eq 0) "Machine Account Quota: $quota" "Set ms-DS-MachineAccountQuota to 0"

Write-Log "`n[*] P-SchemaAdmin" "Yellow"
$schemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -ErrorAction SilentlyContinue
$nonDefault = $schemaAdmins | Where-Object {$_.SamAccountName -ne "Administrator"}
Check-Finding "P-SchemaAdmin" "Critical" "Schema Admins contains non-default accounts" ($nonDefault.Count -eq 0) "Total: $($schemaAdmins.Count) - Non-default: $($nonDefault.SamAccountName -join ', ')" "Remove all non-essential members"

Write-Log "`n[*] A-MinPwdLen" "Yellow"
$policy = Get-ADDefaultDomainPasswordPolicy
Check-Finding "A-MinPwdLen" "Critical" "Password policy permits short passwords" ($policy.MinPasswordLength -ge 12) "Min Length: $($policy.MinPasswordLength)" "Set minimum password length to 12+"

Write-Log "`n[*] P-RecycleBin" "Yellow"
$recycleBin = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}
Check-Finding "P-RecycleBin" "Critical" "AD Recycle Bin is not enabled" ($recycleBin.EnabledScopes.Count -gt 0) "Enabled: $($recycleBin.EnabledScopes.Count -gt 0)" "Enable AD Recycle Bin"

Write-Log "`n[*] P-ServiceDomainAdmin" "Yellow"
$daNoExpiry = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties PasswordNeverExpires | Where-Object {$_.PasswordNeverExpires -eq $true}
Check-Finding "P-ServiceDomainAdmin" "Critical" "Domain Admins with non-expiring passwords" ($daNoExpiry.Count -eq 0) "Count: $($daNoExpiry.Count) - $($daNoExpiry.SamAccountName -join ', ')" "Set password expiry or use gMSA"

Write-Log "`n[*] A-DC-Spooler" "Yellow"
$dcs = Get-ADDomainController -Filter *
$spoolerRunning = @()
foreach ($dc in $dcs) {
    try {
        $svc = Invoke-Command -ComputerName $dc.Name -ScriptBlock { Get-Service -Name Spooler } -ErrorAction Stop
        if ($svc.Status -eq "Running") { $spoolerRunning += $dc.Name }
    } catch {}
}
Check-Finding "A-DC-Spooler" "Critical" "Print Spooler running on DCs" ($spoolerRunning.Count -eq 0) "DCs with Spooler: $($spoolerRunning -join ', ')" "Disable Print Spooler via GPO"

Write-Log "`n[*] P-ProtectedUsers" "Yellow"
$adminAccounts = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object {$_.objectClass -eq "user"}
$protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
$protectedNames = $protectedUsers.SamAccountName
$notProtected = $adminAccounts | Where-Object {$_.SamAccountName -notin $protectedNames}
Check-Finding "P-ProtectedUsers" "Critical" "Admin accounts not in Protected Users" ($notProtected.Count -eq 0) "Not protected: $($notProtected.Count) - $($notProtected.SamAccountName -join ', ')" "Add admin accounts to Protected Users group"

Write-Log "`n[*] P-Delegated" "Yellow"
$notDelegated = Get-ADUser -Filter {AdminCount -eq 1} -Properties AccountNotDelegated | Where-Object {$_.AccountNotDelegated -ne $true}
Check-Finding "P-Delegated" "Critical" "Admin accounts not flagged cannot-be-delegated" ($notDelegated.Count -eq 0) "Not flagged: $($notDelegated.Count) - $($notDelegated.SamAccountName -join ', ')" "Set AccountNotDelegated to true"

Write-Log "`n[*] A-BackupMetadata" "Yellow"
Write-Log "  [?] A-BackupMetadata - Run: repadmin /showbackup *" "Yellow"

Write-Log "`n[*] S-OldNtlm" "Yellow"
try {
    $ntlmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction Stop).LmCompatibilityLevel
    Check-Finding "S-OldNtlm" "Critical" "NTLM authentication level" ($ntlmLevel -ge 5) "LmCompatibilityLevel: $ntlmLevel" "Set LmCompatibilityLevel to 5"
} catch {
    Write-Log "  [?] S-OldNtlm - Check LmCompatibilityLevel registry manually" "Yellow"
}

Write-Log "`n===== HIGH FINDINGS =====" "Magenta"

Write-Log "`n[*] A-AuditDC" "Yellow"
try {
    $auditResult = auditpol /get /subcategory:"Logon" 2>&1
    $configured = $auditResult | Where-Object {$_ -match "Success and Failure"}
    Check-Finding "A-AuditDC" "High" "Advanced audit policy for authentication" ($configured -ne $null) "Logon audit: $(if($configured){'Configured'}else{'Not configured'})" "Configure Advanced Audit Policy via GPO"
} catch {
    Write-Log "  [?] A-AuditDC - Run: auditpol /get /category:*" "Yellow"
}

Write-Log "`n===== MEDIUM FINDINGS =====" "Yellow"

Write-Log "`n[*] A-DCLdapSign" "Yellow"
try {
    $ldapSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity
    Check-Finding "A-DCLdapSign" "Medium" "LDAP signing enforcement" ($ldapSigning -eq 2) "LDAPServerIntegrity: $ldapSigning (2=Required)" "Set LDAP signing to Required via GPO"
} catch {
    Write-Log "  [?] A-DCLdapSign - Set LDAP signing via GPO" "Yellow"
}

Write-Log "`n[*] S-DC-SubnetMissing" "Yellow"
$dcIPs = (Get-ADDomainController -Filter *).IPv4Address
$subnets = Get-ADReplicationSubnet -Filter * -Properties Name
$uncoveredDCs = @()
foreach ($ip in $dcIPs) {
    $covered = $false
    foreach ($subnet in $subnets) {
        $network = $subnet.Name.Split("/")[0]
        if ($ip -like "$($network.Split(".")[0]).$($network.Split(".")[1]).*") { $covered = $true }
    }
    if (!$covered) { $uncoveredDCs += $ip }
}
Check-Finding "S-DC-SubnetMissing" "Medium" "DC IPs not covered by AD subnets" ($uncoveredDCs.Count -eq 0) "Uncovered: $($uncoveredDCs -join ', ')" "Add subnets in AD Sites and Services"

Write-Log "`n[*] S-OS-W10" "Yellow"
$unsupported = Get-ADComputer -Filter {Enabled -eq $true} -Properties OperatingSystem | Where-Object {$_.OperatingSystem -match "Windows 10" -and $_.OperatingSystem -notmatch "Enterprise|Education"}
Check-Finding "S-OS-W10" "Medium" "Unsupported Windows editions" ($unsupported.Count -eq 0) "Count: $($unsupported.Count) - $($unsupported.Name -join ', ')" "Upgrade or retire unsupported editions"

$Total = $Critical + $High + $Medium
Write-Log "`n=================================================" "Cyan"
Write-Log "  AUDIT SUMMARY" "Cyan"
Write-Log "=================================================" "Cyan"
Write-Log "  Critical Issues : $Critical" "Red"
Write-Log "  High Issues     : $High" "Magenta"
Write-Log "  Medium Issues   : $Medium" "Yellow"
Write-Log "  Passed Checks   : $Passed" "Green"
Write-Log "  Total Issues    : $Total" "Yellow"
Write-Log "  Log saved       : $LogFile" "Cyan"
Write-Log "=================================================" "Cyan"
if ($Total -eq 0) {
    Write-Log "  Result: All checks passed!" "Green"
} elseif ($Critical -gt 0) {
    Write-Log "  Result: CRITICAL issues require immediate attention!" "Red"
} else {
    Write-Log "  Result: Review and remediate findings above" "Yellow"
}
Write-Log "=================================================" "Cyan"
