<#
.SYNOPSIS
    Reports Last Logon date and days-since-last-logon for every computer
    object in the domain. Exports results to CSV.

.DESCRIPTION
    Read-only script — queries Active Directory only (Get-ADComputer).
    Makes NO changes to AD (no writes, no object modifications).

    Uses LastLogonTimestamp, which is replicated between Domain
    Controllers (unlike LastLogon, which is per-DC and not replicated).
    This value can lag the true last logon by up to ~14 days by default
    (the replication interval), but is accurate enough for identifying
    stale/inactive machines across the whole domain without having to
    query every DC individually.

.OUTPUT
    CSV file with columns:
        Name, DNSHostName, Enabled, OperatingSystem,
        LastLogonDate, DaysSinceLastLogon, DistinguishedName

.NOTES
    Run from a machine with the ActiveDirectory PowerShell module
    (RSAT) installed, authenticated as a domain user with read access
    (no special/admin rights needed for this query).
#>

# ---- Configuration ----
$OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "AD-ComputerLastLogon_$(Get-Date -Format 'yyyy-MM-dd_HHmm').csv"

# ---- Ensure output folder exists ----
$OutputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "Querying Active Directory for all computer objects..." -ForegroundColor Cyan

# ---- Query AD (read-only) ----
$computers = Get-ADComputer -Filter * -Properties LastLogonTimestamp, OperatingSystem, Enabled, DistinguishedName

Write-Host "Found $($computers.Count) computer objects. Processing..." -ForegroundColor Cyan

$now = Get-Date

$results = foreach ($comp in $computers) {

    if ($comp.LastLogonTimestamp) {
        $lastLogonDate = [DateTime]::FromFileTime($comp.LastLogonTimestamp)
        $daysSince     = [math]::Round(($now - $lastLogonDate).TotalDays, 1)
    }
    else {
        $lastLogonDate = $null
        $daysSince     = $null
    }

    [PSCustomObject]@{
        Name                = $comp.Name
        DNSHostName         = $comp.DNSHostName
        Enabled             = $comp.Enabled
        OperatingSystem     = $comp.OperatingSystem
        LastLogonDate       = if ($lastLogonDate) { $lastLogonDate.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }
        DaysSinceLastLogon  = if ($null -ne $daysSince) { $daysSince } else { 'N/A' }
        DistinguishedName   = $comp.DistinguishedName
    }
}

# ---- Sort: most inactive first (easiest to spot stale machines) ----
$results = $results | Sort-Object {
    if ($_.DaysSinceLastLogon -eq 'N/A') { [double]::MaxValue } else { [double]$_.DaysSinceLastLogon }
} -Descending

# ---- Export ----
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done. Report saved to:" -ForegroundColor Green
Write-Host "  $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Total computers:        $($results.Count)"
Write-Host "  Never logged on:        $(($results | Where-Object { $_.LastLogonDate -eq 'Never' }).Count)"
Write-Host "  Inactive 30+ days:      $(($results | Where-Object { $_.DaysSinceLastLogon -ne 'N/A' -and [double]$_.DaysSinceLastLogon -ge 30 }).Count)"
Write-Host "  Inactive 90+ days:      $(($results | Where-Object { $_.DaysSinceLastLogon -ne 'N/A' -and [double]$_.DaysSinceLastLogon -ge 90 }).Count)"
