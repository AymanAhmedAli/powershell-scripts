# ================================
# disable_inactive_users.ps1
# Author: Ayman Ahmed
# Description: Finds and disables AD users inactive for 30+ days
# Usage: .\disable_inactive_users.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

$InactiveDays = 30
$LogFile = "C:\Logs\disable_inactive_$(Get-Date -Format 'yyyyMMdd').log"
$WhatIf = $true  # Change to $false to actually disable users

# Add your IT team accounts here — these will never be disabled
$ExcludedUsers = @(
    "administrator",
    "krbtgt"
    # "it.admin1", "it.admin2"  ← add your team accounts
)

if (!(Test-Path "C:\Logs")) {
    New-Item -ItemType Directory -Path "C:\Logs" | Out-Null
}

$CutoffDate = (Get-Date).AddDays(-$InactiveDays)

function Write-Log {
    param($Message, $Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $logMessage
}

Write-Log "=================================" "Cyan"
Write-Log "  Inactive Users Report" "Cyan"
Write-Log "  Domain: $env:USERDNSDOMAIN" "Cyan"
Write-Log "  Cutoff Date: $($CutoffDate.ToString('yyyy-MM-dd'))" "Cyan"
Write-Log "  WhatIf Mode: $WhatIf" "Cyan"
Write-Log "=================================" "Cyan"

$inactiveUsers = Get-ADUser -Filter {
    Enabled -eq $true -and
    LastLogonDate -lt $CutoffDate
} -Properties LastLogonDate, PasswordLastSet, Department |
Where-Object { $ExcludedUsers -notcontains $_.SamAccountName.ToLower() }

Write-Log "`n[*] Found $($inactiveUsers.Count) inactive users" "Yellow"

$disabled = 0

foreach ($user in $inactiveUsers) {
    $lastLogon = if ($user.LastLogonDate) {
        $user.LastLogonDate.ToString('yyyy-MM-dd')
    } else { "Never" }

    Write-Log "  [-] $($user.SamAccountName) | Last Logon: $lastLogon | Dept: $($user.Department)" "Red"

    if ($WhatIf) {
        Write-Log "      [WHATIF] Would disable: $($user.SamAccountName)" "Yellow"
    } else {
        try {
            Disable-ADAccount -Identity $user.SamAccountName
            Set-ADUser -Identity $user.SamAccountName `
                -Description "Disabled: Inactive $InactiveDays+ days - $(Get-Date -Format 'yyyy-MM-dd')"
            Write-Log "      [DISABLED] $($user.SamAccountName)" "Green"
            $disabled++
        } catch {
            Write-Log "      [ERROR] Failed to disable $($user.SamAccountName): $_" "Red"
        }
    }
}

Write-Log "`n=================================" "Cyan"
Write-Log "  Summary" "Cyan"
Write-Log "  Inactive Users Found: $($inactiveUsers.Count)" "Yellow"
if ($WhatIf) {
    Write-Log "  WhatIf Mode — No changes made" "Yellow"
    Write-Log "  Set WhatIf to false to apply" "Yellow"
} else {
    Write-Log "  Disabled: $disabled" "Green"
}
Write-Log "  Log: $LogFile" "Cyan"
Write-Log "=================================" "Cyan"

# ================================
# How it works:
# ================================
# 1. Queries all enabled AD users with LastLogonDate older than cutoff
# 2. Skips accounts in ExcludedUsers safelist
# 3. WhatIf=$true → report only, no changes
# 4. WhatIf=$false → disables account + updates description
# 5. All actions logged with timestamp
#
# Configuration:
#   $InactiveDays  — inactivity threshold (default: 30)
#   $WhatIf        — true=report only | false=apply
#   $ExcludedUsers — accounts never disabled
