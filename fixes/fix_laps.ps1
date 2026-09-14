# ================================
# fix_laps.ps1
# Author: Ayman Ahmed
# Description: Deploys Windows LAPS for local admin password management
#              Generates unique random password per computer, stored in AD
# Usage: .\fixes\fix_laps.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
#               Windows Server 2019/2022 or LAPS MSI installed
# ================================

$WhatIf = $true  # Change to $false to apply fix

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Windows LAPS Deployment" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Step 1: Check OS
Write-Host "`n[STEP 1] Checking LAPS availability..." -ForegroundColor Yellow
$osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
Write-Host "    OS: $osVersion"

$lapsBuiltIn = $osVersion -match "2022|2019|Windows 11"
if ($lapsBuiltIn) {
    Write-Host "    [OK] Windows LAPS built-in supported" -ForegroundColor Green
} else {
    Write-Host "    [!] Legacy LAPS MSI required" -ForegroundColor Yellow
    Write-Host "        Download: https://www.microsoft.com/en-us/download/details.aspx?id=46899" -ForegroundColor Cyan
}

# Step 2: Check AD Schema
Write-Host "`n[STEP 2] Checking AD Schema for LAPS attributes..." -ForegroundColor Yellow
$schemaAttributes = @("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword")
$lapsConfigured = $false

foreach ($attr in $schemaAttributes) {
    try {
        $schemaNC = (Get-ADRootDSE).schemaNamingContext
        $exists = Get-ADObject -Filter {lDAPDisplayName -eq $attr} `
            -SearchBase $schemaNC -ErrorAction Stop
        if ($exists) {
            Write-Host "    [OK] $attr - present in schema" -ForegroundColor Green
            $lapsConfigured = $true
        }
    } catch {
        Write-Host "    [!] $attr - NOT in schema" -ForegroundColor Red
    }
}

if (!$lapsConfigured) {
    Write-Host "`n    [!] LAPS not configured in AD schema" -ForegroundColor Red
}

# Step 3: Enable LAPS in AD
Write-Host "`n[STEP 3] Enabling Windows LAPS in AD..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "    [WHATIF] Would run: Update-LapsADSchema" -ForegroundColor Yellow
    Write-Host "    [WHATIF] Would set permissions on: $(Get-ADDomain).DistinguishedName" -ForegroundColor Yellow
} else {
    try {
        Update-LapsADSchema -Confirm:$false
        Write-Host "    [OK] LAPS AD schema updated ✅" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Update-LapsADSchema failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "        Install LAPS MSI first, then run: Update-AdmPwdADSchema" -ForegroundColor Yellow
    }
}

# Step 4: Set permissions
Write-Host "`n[STEP 4] Setting LAPS permissions..." -ForegroundColor Yellow
$targetOU = (Get-ADDomain).DistinguishedName
$readGroup = "Domain Admins"

if ($WhatIf) {
    Write-Host "    [WHATIF] Would set read permission on: $targetOU" -ForegroundColor Yellow
    Write-Host "    [WHATIF] Read group: $readGroup" -ForegroundColor Yellow
} else {
    try {
        Set-LapsADComputerSelfPermission -Identity $targetOU
        Write-Host "    [OK] Computer self-write permission set ✅" -ForegroundColor Green
        Set-LapsADReadPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup
        Write-Host "    [OK] Read permission granted to: $readGroup ✅" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Permission setup failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Step 5: GPO steps
Write-Host "`n[STEP 5] GPO Configuration (manual steps)..." -ForegroundColor Yellow
Write-Host "    1. Open Group Policy Management" -ForegroundColor White
Write-Host "    2. Create GPO: 'Deploy-LAPS'" -ForegroundColor White
Write-Host "    3. Computer Configuration > Administrative Templates > System > LAPS" -ForegroundColor White
Write-Host "    4. Enable: Configure password backup directory > Active Directory" -ForegroundColor White
Write-Host "    5. Enable: Password Settings > Length: 14, Age: 30 days" -ForegroundColor White
Write-Host "    6. Link GPO to Computers OU" -ForegroundColor White

# Step 6: How to read passwords
Write-Host "`n[STEP 6] Reading LAPS passwords after deployment..." -ForegroundColor Yellow
Write-Host "    Get-LapsADPassword -Identity COMPUTERNAME -AsPlainText" -ForegroundColor Cyan

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# Problem without LAPS:
#   Every computer has same local admin password.
#   One compromised machine = all machines compromised.
#   Pass-the-hash attacks become trivial.
#
# LAPS solution:
#   Each computer generates its own random password.
#   Password stored encrypted in AD attribute.
#   Auto-rotated every 30 days.
#   Only authorized admins can read it.
#
# Two versions:
#   Legacy LAPS: ms-Mcs-AdmPwd (plaintext in AD)
#   Windows LAPS: msLAPS-EncryptedPassword (encrypted in AD)
#   Use Windows LAPS on Server 2019/2022+
#
# Impact: ⚠️ Medium - requires LAPS MSI on older systems
#
# Verification after deployment:
#   Get-LapsADPassword -Identity COMPUTERNAME -AsPlainText
#   Expected: unique password per computer
#
# Event IDs:
#   10018 = LAPS password updated successfully
#   4662  = AD object access (password read)
