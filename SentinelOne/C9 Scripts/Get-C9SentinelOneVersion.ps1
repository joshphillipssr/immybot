<#
.SYNOPSIS
    A Metascript function that retrieves the installed version of the SentinelOne agent from an endpoint.
.DESCRIPTION
    This function is designed to be called from a Metascript context. It uses Invoke-ImmyCommand
    to execute detection logic on the endpoint. It reliably finds the agent's version by querying
    the running service for its executable path and then reading the file's version metadata.
.RETURNS
    [string] The product version of the SentinelOne agent if found (e.g., "24.2.3.471").
    $null if the agent is not found or if the version cannot be determined.
.EXAMPLE
    $installedVersion = Get-C9SentinelOneVersion
    if ($installedVersion) {
        Write-Host "Detected SentinelOne Version: $installedVersion"
    } else {
        Write-Warning "Could not detect an installed SentinelOne agent."
    }
#>
function Get-C9SentinelOneVersion {
    [CmdletBinding()]
    param()

    write-host "Attempting to get S1 version from endpoint..."
    
    # Use the standard "bridge" to run detection logic on the endpoint.
    $version = Invoke-ImmyCommand -ScriptBlock {
        # This entire script block runs on the endpoint as SYSTEM.
        try {
            # Find the service to get the authoritative path to the executable.
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

            if ($service -and $service.PathName) {
                $exePath = $service.PathName.Trim('"')
                
                # Verify the path reported by the service actually exists.
                if (Test-Path -LiteralPath $exePath) {
                    # Get the file's version info. This is the most reliable source.
                    $fileInfo = Get-Item -LiteralPath $exePath -ErrorAction SilentlyContinue
                    $productVersion = $fileInfo.VersionInfo.ProductVersion
                    
                    if ($productVersion) {
                        # SUCCESS: We have the version. Return it to the Metascript.
                        return $productVersion
                    }
                }
            }
            
            # If any of the above steps fail, we fall through to here.
            # Return $null to indicate the agent was not found or version is unknown.
            return $null

        } catch {
            # In case of an unexpected terminating error, log it and return null.
            Write-Warning "An unexpected error occurred during endpoint detection: $_"
            return $null
        }
    }

    if ($version) {
        write-host "Successfully retrieved version: $version"
    } else {
        Write-Host "SentinelOne agent not found or version could not be determined."
    }

    return $version
}