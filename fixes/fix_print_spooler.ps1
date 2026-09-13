# ================================
# fix_print_spooler.ps1
# Author: Ayman Ahmed
# Description: Disables Print Spooler service on Domain Controllers
#              Prevents PrinterBug/SpoolSample coercion attacks
# Usage: .\fixes\fix_print_spooler.ps1
# Requirements: PowerShell 5.1+, Domain Admin, WinRM enabled on DCs
# WARNING: Verify no printers hosted on DC before applying
# ================================

$WhatIf = $true  # Change to $false to apply fix

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: Disable Print Spooler on DCs" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$dcs = Get-ADDomainController -Filter *
Write-Host "`n[*] Checking Print Spooler on $($dcs.Count) DC(s)..." -ForegroundColor Yellow

foreach ($dc in $dcs) {
    Write-Host "`n  [*] DC: $($dc.Name) ($($dc.IPv4Address))" -ForegroundColor Yellow

    try {
        $status = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            $svc = Get-Service -Name Spooler
            return @{ Status = $svc.Status; StartType = $svc.StartType }
        } -ErrorAction Stop

        Write-Host "      Status:    $($status.Status)" -ForegroundColor $(
            if ($status.Status -eq "Running") {"Red"} else {"Green"}
        )
        Write-Host "      StartType: $($status.StartType)"

        if ($status.Status -ne "Running" -and $status.StartType -eq "Disabled") {
            Write-Host "      [OK] Already disabled" -ForegroundColor Green
        } else {
            if ($WhatIf) {
                Write-Host "      [WHATIF] Would stop and disable Print Spooler" -ForegroundColor Yellow
            } else {
                Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                    Stop-Service -Name Spooler -Force
                    Set-Service -Name Spooler -StartupType Disabled
                } -ErrorAction Stop
                Write-Host "      [OK] Print Spooler stopped and disabled ✅" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "      [!] Cannot connect: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Done" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Gets all Domain Controllers from AD
# 2. Checks Print Spooler status on each DC via WinRM
# 3. WhatIf=$true → shows what would be changed
# 4. WhatIf=$false → stops and disables via Invoke-Command
#
# Why this matters:
#   Print Spooler on DCs is exploitable via:
#   → PrinterBug (SpoolSample) — forces DC to authenticate to attacker
#   → PetitPotam — NTLM relay to compromise the domain
#   These attacks can lead to full domain takeover.
#
# Note: Stop-Service -ComputerName deprecated in newer PowerShell.
#   Using Invoke-Command instead for remote execution.
#
# Impact: ⚠️ Medium — verify no DC-based printing first
#   Check with: Get-Printer -ComputerName DC_NAME
#
# Verification:
#   Invoke-Command -ComputerName DC_NAME -ScriptBlock { Get-Service Spooler }
#   Expected: Status=Stopped, StartType=Disabled

