# =================================================================================
# Name:     C9SP-SentinelOne-ConfigTask-Test Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

# SentinelOne Agent Version Detection Script (ImmyBot-Compatible)
#
# Returns a version STRING if an agent is detected.
# Returns $null if no definitive agent presence is found.

# Set the preference to ensure our verbose messages are always shown in logs.
$VerbosePreference = 'Continue'

Write-Verbose "--- S1 Detection Script Started ---"

try {

    Write-Verbose "[Step 1] Querying for the 'SentinelAgent' service using Get-CimInstance."
    
    # Query for the service, but pipe to Out-Null to suppress the object output.
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

    if ($service -and $service.PathName) {
        # LOGGING: Service was found.
        Write-Verbose "[Step 1] SUCCESS: 'SentinelAgent' service found."
        Write-Verbose "[Step 2] Service PathName is: $($service.PathName)"

        $exePath = $service.PathName.Trim('"')
        Write-Verbose "[Step 2] Cleaned executable path is: $exePath"

        # LOGGING: Announce the path check.
        Write-Verbose "[Step 3] Checking if path '$exePath' exists on disk..."
        
        # Use -LiteralPath for robustness against special characters in the path.
        if (Test-Path -LiteralPath $exePath) {
            # LOGGING: Path is valid.
            Write-Verbose "[Step 3] SUCCESS: Path is valid."
            Write-Verbose "[Step 4] Attempting to get file version info for the executable."
            
            # Get file properties.
            $fileInfo = Get-Item -LiteralPath $exePath -ErrorAction SilentlyContinue
            $version = $fileInfo.VersionInfo.ProductVersion
            
            if ($version) {
                # LOGGING: Version was successfully extracted.
                Write-Verbose "[Step 4] SUCCESS: Found version '$version'."
                Write-Verbose "--- S1 Detection Script PASSED. Returning version string. ---"
                
                # This is the ONLY line that writes to the success stream.
                return $version
            }
            else {
                # LOGGING: Failed to get version from the file.
                Write-Verbose "[Step 4] FAILED: Could not extract version info from the file object. FileInfo was: $($fileInfo | Out-String)"
            }
        }
        else {
            # LOGGING: The path from the service does not exist.
            Write-Verbose "[Step 3] FAILED: The path '$exePath' reported by the service does not exist."
        }
    }
    else {
        # LOGGING: Service was not found.
        Write-Verbose "[Step 1] FAILED: The 'SentinelAgent' service was not found."
    }

    # LOGGING: Final failure path.
    Write-Verbose "--- S1 Detection Script FAILED. Returning null. ---"
    # If any check fails, return null. This writes $null to the stream.
    return $null
}
catch {
    # LOGGING: An unexpected error occurred.
    Write-Verbose "--- S1 Detection Script FAILED due to an unexpected error. ---"
    Write-Verbose "ERROR: $($_.Exception.Message)"
    Write-Verbose "STACKTRACE: $($_.ScriptStackTrace)"
    
    # On any unexpected/terminating error, return null to signal "not found".
    return $null
}