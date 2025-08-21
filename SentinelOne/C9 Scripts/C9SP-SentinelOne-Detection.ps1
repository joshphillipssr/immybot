# =================================================================================
# Name:     C9SP-SentinelOne-Detection Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# Purpose:  Detects SentinelOne agent presence and version on an endpoint. Returns `$Null` for a clean
#           system to trigger a fresh installation or returns a version string to trigger an update or
#           remediation.
# =================================================================================

# Hardcoded fallback version used when remnants of SentinelOne are detected but no version information
# can be extracted. This value must correspond to an existing package version so that the deployment
# pipeline routes the device to the appropriate remediation "Test" script. In future, if registry
# permissions are fixed and the installer can read version keys directly, this fallback mechanism can
# be removed.
$fallbackVersion = "25.1.3.334"

try {
    # Import the helper modules that expose metadata and display functions needed for detection.
    Write-Host "[$ScriptName] Importing helper modules..."
    Import-Module "C9MetascriptHelpers" -ErrorAction Stop -Verbose:$false
    Import-Module "C9SentinelOneMeta"   -ErrorAction Stop -Verbose:$false

    # --- Step 1: Gather Comprehensive Status ---
    # Obtain a detailed status object by calling Get-C9S1ComprehensiveStatus. This returns flags indicating
    # whether the agent or remnants are present and includes version strings from multiple sources (service
    # binary and sentinelctl).
    Write-Host "[$ScriptName] Gathering comprehensive SentinelOne status from the endpoint..."
    $s1Status = Get-C9S1ComprehensiveStatus

    # Format and output the status object to the console for diagnostic visibility. This section
    # outputs a formatted table so that logs clearly show the detection results in production.
    $formattedStatus = Format-C9ObjectForDisplay -InputObject $s1Status | Format-Table -AutoSize | Out-String
    Write-Host "----------------- S1 STATUS REPORT -----------------"
    Write-Host $formattedStatus
    Write-Host "----------------------------------------------------"
    # --- END: Diagnostic Logging Block ---

    # --- Step 2: Determine whether SentinelOne is installed ---
    # If IsPresentAnywhere is `$false`, neither the agent nor any remnants are detected. In this case,
    # return `$Null` to signal to the deployment workflow that a fresh installation should proceed.
    if (-not $s1Status.IsPresentAnywhere) {
        Write-Host -ForegroundColor Green "[$ScriptName] [CLEAN] No evident of SentinelOne found. Returning `$Null to proceed with installation."
        return $Null
    }

    # --- Step 3: Remnants Found - Determine Installed Version ---
    # At this point IsPresentAnywhere is `$true`, so either the agent or remnants are detected and we need
    # to return a version string.
    Write-Host "[$ScriptName] [DETECTED] Evidence of SentinelOne was found. Attempting to identify a version..."

    # First attempt to read VersionFromService (pulled from the SentinelAgent service executable), which is the most reliable source.
    if (-not [string]::IsNullOrWhiteSpace($s1Status.VersionFromService)) {
        $versionToReturn = $s1Status.VersionFromService
        Write-Host -ForegroundColor Green "[$ScriptName] [SUCCESS] Found version '$versionToReturn' from the SentinelAgent service."
        return $versionToReturn
    }
    
    # If VersionFromService is unavailable or empty, attempt to read VersionFromCtl (reported by sentinelctl.exe) as a secondary source.
    if (-not [string]::IsNullOrWhiteSpace($s1Status.VersionFromCtl)) {
        $versionToReturn = $s1Status.VersionFromCtl
        Write-Host -ForegroundColor Green "[$ScriptName] [SUCCESS] Found version '$versionToReturn' from sentinelctl.exe."
        return $versionToReturn
    }

    # --- Step 4: Fallback for Unversioned Remnants ---
    # Reaching this point means the agent or its remnants were detected but both version sources were empty.
    # This typically indicates a broken or partial installation requiring remediation. Return the hardcoded
    # fallback version to force the deployment workflow to route the endpoint to the remediation "Test" script.
    Write-Warning "[$ScriptName] [BROKEN] SentinelOne remnants are present, but a version could not be determined."
    Write-Warning "[$ScriptName] Returning fallback version '$fallbackVersion' to route the machine to the Test script for remediation."
    return $fallbackVersion

} catch {
    # --- Catastrophic Failure Fallback ---
    # Any unhandled exception during detection indicates the script could not reliably determine the agent
    # status. To avoid performing any action on an unknown state, return the fallback version so the
    # endpoint is routed to the remediation script where logs can be inspected manually.
    Write-Error "[$ScriptName] A catastrophic error occurred during the detection process. Error details: $_"
    Write-Error "[$ScriptName] Returning fallback version '$fallbackVersion' as a fail-safe to route to the Test script for inspection."
    return $fallbackVersion
}