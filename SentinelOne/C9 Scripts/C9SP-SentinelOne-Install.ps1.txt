# =================================================================================
# C9SP-SentinelOne-Install.ps1 (Final, Self-Sufficient Architecture)
# Author: Josh Phillips, Cloud 9
# Project: T20250611.0014
#
# This script is 100% self-reliant. It ignores the platform's broken download
# process and instead orchestrates the entire download and install itself.
# =================================================================================
$VerbosePreference = 'Continue'

# Import our custom toolkits
Import-Module C9SentinelOneMeta
Import-Module C9MetascriptHelpers

Write-Host "--- C9-S1 Self-Sufficient Install Script Started ---"
Write-Host "Target Version determined by ImmyBot Engine: $DisplayVersion"

try {
    # --- Phase 1: Get Download URL and Authentication Header from our Integration ---
    Write-Host "[FETCH] Calling our integration to get all available versions..."
    $allVersions = Get-IntegrationDynamicVersions -ErrorAction Stop
    $targetVersionInfo = $allVersions | Where-Object { $_.Version -eq $DisplayVersion }

    if (-not $targetVersionInfo) {
        throw "Could not find package info for version '$DisplayVersion' from our integration."
    }

    $downloadUrl = $targetVersionInfo.Url
    $fileName = $targetVersionInfo.FileName
    Write-Host "Found package info. URL: $downloadUrl"

    Write-Host "[AUTH] Calling our integration to get the download authentication header..."
    # The 'Get-IntegrationAuthHeader' cmdlet is available because we defined the -GetAuthHeader capability.
    $authHeader = Get-IntegrationAuthHeader -ErrorAction Stop
    if (-not $authHeader) { throw "Failed to retrieve authentication header from the integration." }
    
    # --- Phase 2: Ensure the Installer is Available on the Endpoint ---
    Write-Host "[RESOLVE] Calling Resolve-InstallerAvailable to ensure installer is staged..."
    $stagedInstallerPath = Resolve-InstallerAvailable -DownloadUrl $downloadUrl -FileName $fileName -AuthHeader $authHeader
    Write-Host "[SUCCESS] Installer is confirmed to be available at: $stagedInstallerPath"

    # --- Phase 3: Get Install Token and Execute ---
    Write-Host "Retrieving site-specific installation token..."
    $siteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($siteToken)) { throw "Did not receive a valid Site Token." }
    
    $argumentList = "-t `"$siteToken`" -f --qn --log `"$InstallerLogFile`""

    Write-Host "--- Installation Parameters ---"
    Write-Host "Installer Path: `"$stagedInstallerPath`""
    Write-Host "Full Command: `"$stagedInstallerPath`" $argumentList"
    Write-Host "-------------------------------"

    Start-ProcessWithLogTailContext -Path $stagedInstallerPath -ArgumentList $argumentList -LogFilePath $InstallerLogFile -TimeoutSeconds 900
    
    Write-Host "[SUCCESS] Installation process completed."

} catch {
    $errorMessage = "A fatal error occurred in the Self-Sufficient Installation Script: $([string]$_)"
    Write-Error $errorMessage
    throw $errorMessage
}