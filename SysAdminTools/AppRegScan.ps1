<#
.SYNOPSIS
    Searches the Windows registry for installed products matching a given search pattern.

.DESCRIPTION
    This script enumerates installed products by reading raw MSI product registration data from both
    per-machine and per-user registry hives. It supports matching product names with a user-specified
    wildcard search pattern. Intended for scenarios where detection of specific software (e.g., ImmyBot Agent)
    is required. Must be run in user context to detect per-user installs.

.PARAMETER ProductSearchPattern
    The wildcard search pattern to match product DisplayName values against.
    Default is '*Immy*'. This parameter supports any valid wildcard pattern.

.EXAMPLE
    .\AppRegScan.ps1 -ProductSearchPattern "*Immy*"
    Scans all relevant registry hives for installed products matching the pattern '*Immy*'.

.NOTES
    Author: Josh Phillips
    Date: 08/11/2025
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProductSearchPattern
)

# Coalesce from Ninja form variable if not provided as a script parameter
if (-not $PSBoundParameters.ContainsKey('ProductSearchPattern') -or [string]::IsNullOrWhiteSpace($ProductSearchPattern)) {
    $ProductSearchPattern = $env:productSearchPattern
}
if ([string]::IsNullOrWhiteSpace($ProductSearchPattern)) {
    $ProductSearchPattern = '*Immy*'
}
$ProductSearchPattern = $ProductSearchPattern.Trim()
Write-Host "Using product search pattern: '$ProductSearchPattern'"

$results = @()

$searchPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

# Get products from all specified registry hives.
$productKeys = Get-ChildItem -Path $searchPaths -ErrorAction SilentlyContinue

Write-Host "Searching $($productKeys.Count) registry keys across all installation contexts..."

foreach ($key in $productKeys) {
    $productName = $key.GetValue("DisplayName")
    
    # We check for a DisplayName because keys without one are usually just patches.
    if (-not [string]::IsNullOrWhiteSpace($productName)) {
        $results += [PSCustomObject]@{
            Name              = $productName
            Version           = $key.GetValue("DisplayVersion")
            Publisher         = $key.GetValue("Publisher")
            UninstallString   = $key.GetValue("UninstallString")
            ProductCode       = $key.PSChildName
        }
    }
}

if ($results) {
    Write-Host -ForegroundColor Green "Found $($results.Count) registered products. Displaying list:"
    $results | Sort-Object Name | Format-Table Name, Version, Publisher -AutoSize

    # Filter results by the provided pattern
    $matchingProducts = $results | Where-Object { $_.Name -like $ProductSearchPattern }
    if ($matchingProducts) {
        Write-Host -ForegroundColor Cyan "`n--- Matching Products (Pattern: '$ProductSearchPattern') ---"
        $matchingProducts | Format-List
    } else {
        Write-Host -ForegroundColor Yellow "`nNo products matched pattern '$ProductSearchPattern' in any registry context."
    }
} else {
    Write-Host -ForegroundColor Red "Could not find any products with a DisplayName in the registry. This indicates severe corruption."
}