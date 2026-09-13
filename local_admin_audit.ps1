# ================================
# local_admin_audit.ps1
# Author: Ayman Ahmed
# Description: Audits local administrators on domain computers
# Usage: .\local_admin_audit.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin, WinRM
# ================================

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Local Admin Audit Report" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties Name, OperatingSystem
Write-Host "`n[*] Found $($computers.Count) computers to audit" -ForegroundColor Yellow

$results = @()

foreach ($computer in $computers) {
    Write-Host "`n  [*] Checking: $($computer.Name)" -ForegroundColor Yellow

    try {
        $admins = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
            $output = net localgroup Administrators 2>&1
            $members = $output | Select-String -Pattern "^(?!Alias|Comment|Members|---|The command)" |
                       Where-Object { $_.ToString().Trim() -ne "" }
            $members | ForEach-Object { $_.ToString().Trim() }
        } -ErrorAction Stop

        foreach ($admin in $admins) {
            $results += [PSCustomObject]@{
                Computer = $computer.Name
                OS       = $computer.OperatingSystem
                Member   = $admin
            }
            $color = if ($admin -match "Domain Admins|Administrator|Enterprise") {"Gray"} else {"Red"}
            Write-Host "    - $admin" -ForegroundColor $color
        }
    } catch {
        Write-Host "    [!] Cannot connect: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

$reportPath = "C:\Logs\local_admin_audit_$(Get-Date -Format 'yyyyMMdd').csv"
if (!(Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" | Out-Null }
$results | Export-Csv -Path $reportPath -NoTypeInformation

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "  Computers Audited: $($computers.Count)" -ForegroundColor Yellow
Write-Host "  Total Admin Entries: $($results.Count)" -ForegroundColor Yellow
Write-Host "  Report saved: $reportPath" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Queries all enabled computers from AD
# 2. Connects via WinRM using Invoke-Command
# 3. Uses 'net localgroup Administrators' to list members
# 4. Flags non-standard accounts in red
# 5. Exports full results to CSV
#
# Known Limitations:
#   → Requires WinRM enabled on target computers
#   → Get-LocalGroupMember fails on DCs (use net localgroup instead)
#   → Offline computers show "Cannot connect"
#   → Domain Admins/Enterprise Admins in local Administrators = expected
#
# What to look for:
#   → Unknown user accounts (not Domain Admins or Administrator)
#   → Personal accounts with local admin rights
#   → Service accounts with local admin rights
