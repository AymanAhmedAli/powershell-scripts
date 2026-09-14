# ================================
# fix_ad_subnets.ps1
# Author: Ayman Ahmed
# Description: Adds missing DC subnets to AD Sites and Services
#              Fixes replication routing and site awareness
# Usage: .\fixes\fix_ad_subnets.ps1
# Requirements: PowerShell 5.1+, RSAT AD module, Domain Admin
# ================================

$WhatIf = $true  # Change to $false to apply fix

# Define your DC subnets here
# Format: Subnet (CIDR), Site name, Description
$Subnets = @(
    @{ Subnet = "10.0.0.0/24";   Site = "Default-First-Site-Name"; Description = "Main Site" }
    @{ Subnet = "192.168.1.0/24"; Site = "Default-First-Site-Name"; Description = "Branch Site" }
    # Add more subnets as needed
)

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  Fix: AD Sites and Subnets" -ForegroundColor Cyan
Write-Host "  Domain: $env:USERDNSDOMAIN" -ForegroundColor Cyan
Write-Host "  WhatIf Mode: $WhatIf" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check existing subnets
Write-Host "`n[STEP 1] Current AD Subnets:" -ForegroundColor Yellow
$existingSubnets = Get-ADReplicationSubnet -Filter * -Properties Name, Site, Description
if ($existingSubnets.Count -eq 0) {
    Write-Host "    No subnets defined" -ForegroundColor Red
} else {
    foreach ($s in $existingSubnets) {
        Write-Host "    > $($s.Name) | Site: $($s.Site)" -ForegroundColor Gray
    }
}

# Check DC IPs
Write-Host "`n[STEP 2] Domain Controller IPs:" -ForegroundColor Yellow
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    Write-Host "    > $($dc.Name): $($dc.IPv4Address)" -ForegroundColor Yellow
}

# Add missing subnets
Write-Host "`n[STEP 3] Adding missing subnets..." -ForegroundColor Yellow

$added = 0
$exists = 0

foreach ($subnet in $Subnets) {
    $existing = $existingSubnets | Where-Object { $_.Name -eq $subnet.Subnet }

    if ($existing) {
        Write-Host "  [OK] $($subnet.Subnet) - already exists" -ForegroundColor Green
        $exists++
    } else {
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would add: $($subnet.Subnet) > Site: $($subnet.Site)" -ForegroundColor Yellow
        } else {
            New-ADReplicationSubnet `
                -Name $subnet.Subnet `
                -Site $subnet.Site `
                -Description $subnet.Description
            Write-Host "  [OK] Added: $($subnet.Subnet) ✅" -ForegroundColor Green
            $added++
        }
    }
}

if (!$WhatIf) {
    Write-Host "`n[STEP 4] Verification:" -ForegroundColor Yellow
    $newSubnets = Get-ADReplicationSubnet -Filter * -Properties Name, Site
    foreach ($s in $newSubnets) {
        Write-Host "    > $($s.Name)" -ForegroundColor Green
    }
}

Write-Host "`n=================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
if ($WhatIf) {
    $toAdd = ($Subnets | Where-Object { $_.Subnet -notin $existingSubnets.Name }).Count
    Write-Host "  Would Add: $toAdd subnets" -ForegroundColor Yellow
} else {
    Write-Host "  Already Existed: $exists" -ForegroundColor Green
    Write-Host "  Newly Added:     $added" -ForegroundColor Green
}
Write-Host "=================================" -ForegroundColor Cyan

# ================================
# How it works:
# ================================
# 1. Lists existing subnets in AD Sites and Services
# 2. Lists all DC IPs for reference
# 3. Compares defined subnets with existing
# 4. WhatIf=$true > shows what would be added
# 5. WhatIf=$false > adds missing subnets and verifies
#
# Why this matters:
#   Without subnets: clients may authenticate against far DCs (slow)
#   With subnets: clients find nearest DC automatically
#   Also fixes Event ID 5807 warnings in System log
#
# Configuration:
#   Edit $Subnets array to match your environment
#   Add all network ranges where DCs reside
#
# Impact: ✅ Zero - safe to apply immediately
#
# Verification:
#   Get-ADReplicationSubnet -Filter * | Select Name, Site
