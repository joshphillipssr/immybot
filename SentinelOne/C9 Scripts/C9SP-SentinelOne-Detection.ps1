# =================================================================================
# Name:     C9SP-SentinelOne-Detection Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

$VerbosePreference = 'Continue'
$DebugPreference = 'Continue'

# This is the hardcoded version to return for broken/unversioned installations.
# It must match a version available in the software package to route to the Test script correctly.
$fallbackVersion = "24.2.3.471"

try {
    # Import the necessary helper modules. 
    Write-Host "[$ScriptName] Importing helper modules..."
    Import-Module "C9MetascriptHelpers" -ErrorAction Stop -Verbose:$false
    Import-Module "C9SentinelOneMeta"   -ErrorAction Stop -Verbose:$false

    # --- Step 1: Gather Comprehensive Status ---
    Write-Host "[$ScriptName] Gathering comprehensive SentinelOne status from the endpoint..."
    $s1Status = Get-C9S1ComprehensiveStatus

    # --- Step 2: The Main Decision ---
    # Check the single source of truth for agent presence.
    if (-not $s1Status.IsPresentAnywhere) {
        Write-Host -ForegroundColor Green "[$ScriptName] [CLEAN] No SentinelOne remnants found. Returning `$False to proceed with installation."
        return $False
    }

    # --- Step 3: Remnants Found - Find a Version ---
    # If we are here, IsPresentAnywhere was $true. We must return a version number.
    Write-Host "[$ScriptName] [DETECTED] SentinelOne remnants were found. Attempting to identify a version..."

    # Prioritize the most reliable version source first (from the service EXE).
    if (-not [string]::IsNullOrWhiteSpace($s1Status.VersionFromService)) {
        $versionToReturn = $s1Status.VersionFromService
        Write-Host -ForegroundColor Green "[$ScriptName] [SUCCESS] Found version '$versionToReturn' from the SentinelAgent service."
        return $versionToReturn
    }
    
    # Fall back to the version from sentinelctl if the service version wasn't available.
    if (-not [string]::IsNullOrWhiteSpace($s1Status.VersionFromCtl)) {
        $versionToReturn = $s1Status.VersionFromCtl
        Write-Host -ForegroundColor Green "[$ScriptName] [SUCCESS] Found version '$versionToReturn' from sentinelctl.exe."
        return $versionToReturn
    }

    # --- Step 4: Fallback for Unversioned Remnants ---
    # If we're here, remnants exist, but we couldn't parse a specific version.
    # This indicates a broken or partial installation that requires remediation.
    Write-Warning "[$ScriptName] [BROKEN] SentinelOne remnants are present, but a version could not be determined."
    Write-Warning "[$ScriptName] Returning fallback version '$fallbackVersion' to route the machine to the Test script for remediation."
    return $fallbackVersion

} catch {
    # --- Catastrophic Failure Fallback ---
    # If the detection script itself fails, it is safest to route to the Test script for manual log inspection.
    # This prevents an unintended installation attempt on a machine with an unknown state.
    Write-Error "[$ScriptName] A catastrophic error occurred during the detection process. Error details: $_"
    Write-Error "[$ScriptName] Returning fallback version '$fallbackVersion' as a fail-safe to route to the Test script for inspection."
    return $fallbackVersion
}