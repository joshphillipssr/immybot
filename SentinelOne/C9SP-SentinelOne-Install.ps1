#Requires -Version 5.1
<#
.SYNOPSIS
    The definitive installation script for the C9SP-SentinelOne software package.
.DESCRIPTION
    This script runs in the Metascript context and follows the definitive architectural pattern
    for an "Installation Script". It is context-pure and robust.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    4.4.0 - Added preflight logic
#>

# =================================================================================
# --- METASCRIPT CONTEXT (This section is architecturally sound) ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

# Preflight check
# Import the module containing our helper functions
Import-Module C9SentinelOne

# Run the pre-flight check
$preFlightCheck = Test-S1InstallPreFlight
Write-Verbose "Pre-flight check result: $($preFlightCheck.Reason)"

# If the check says to stop, we exit gracefully.
if ($preFlightCheck.ShouldStop) {
    Write-Warning "Halting script based on pre-flight check."
    # We use 'return' to exit this script cleanly without throwing an error
    return
}

# --- If we get here, it's safe to proceed with the rest of the install logic ---
Write-Verbose "Pre-flight check passed. Continuing with installation..."


try {
    Write-Verbose "--- C9-S1 Installation Metascript Started ---"

    # Step 1: Get the site-specific installation token.
    Write-Verbose "Calling Get-IntegrationAgentInstallToken to retrieve site token..."
    # The capability is ISupportsTenantInstallToken, but the cmdlet is Get-IntegrationAgentInstallToken.
    $SiteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($SiteToken)) {
        throw "Get-IntegrationAgentInstallToken did not return a site token. Check integration audit log."
    }
    Write-Verbose "Successfully retrieved site token."

    # Step 2: Build the argument list.
    $ArgumentList = ''
    Write-Verbose "Building arguments for modern EXE installer version $DisplayVersion..."
    # The $DisplayVersion variable is automatically provided in this context.
    switch -regex ($DisplayVersion) {
        '^22\.1' {
            Write-Verbose "Version is 22.1. Using mandatory --dont_fail_on_config_preserving_failures flag."
            $ArgumentList = "--dont_fail_on_config_preserving_failures -t `"$SiteToken`" -f --qn"
        }
        default { # For all newer versions (22.2+).
            Write-Verbose "Version is 22.2 or newer. Using modern arguments."
            # Quoting the site token to handle any special characters.
            $ArgumentList = "-t `"$SiteToken`" -f --qn"
        }
    }
    Write-Host "Final argument list constructed: $ArgumentList"

    # Step 3: Invoke the installation logic on the endpoint.
    Write-Host "Invoking self-contained installation logic on the endpoint..."
    $installResult = Invoke-ImmyCommand -ScriptBlock {
        # =========================================================================
        # --- SYSTEM CONTEXT SCRIPTBLOCK (Corrected Structure) ---
        # =========================================================================

        # These variables are correctly passed from the Metascript using the $using: scope modifier.
        $InstallerPath = $using:InstallerFile
        $ArgumentListString = $using:ArgumentList # Passing as a single string

        # Use a transcript for maximum visibility on the endpoint
        $logDir = "C:\ProgramData\ImmyBot\S1"
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $logFile = Join-Path -Path $logDir -ChildPath "s1_install_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Start-Transcript -Path $logFile -Force

        # A SINGLE, UNIFIED TRY/CATCH/FINALLY BLOCK
        try {
            Write-Verbose "Installer Path: $InstallerPath"
            Write-Verbose "Arguments: $ArgumentListString"

            # Start the process and get the process object.
            $process = Start-Process -FilePath $InstallerPath -ArgumentList $ArgumentListString -NoNewWindow -PassThru -Wait

            # The -Wait parameter can be used here because --qn makes the installer non-interactive.
            # If it were to hang, we would switch to the active wait loop. For now, this is cleaner.
            
            $exitCode = $process.ExitCode
            Write-Host "Installer process finished with exit code: $exitCode"

            # Check for success exit codes (e.g., 0, 12, or pending reboot codes)
            $successCodes = @(0, 12, 100, 101, 103, 104, 202)
            if ($successCodes -contains $exitCode) {
                Write-Host "[SUCCESS] Installation was successful or a reboot is pending."
                return $true # Return a simple boolean back to the Metascript
            } else {
                # Throw a detailed error for any other exit code
                throw "Installation failed with a critical exit code: $exitCode. See transcript '$logFile' on endpoint for details."
            }
        }
        catch {
            # This SINGLE catch block will handle any error within the 'try'
            throw "A fatal error occurred on the endpoint during installation: $_"
        }
        finally {
            # This SINGLE finally block will always run to stop the transcript
            Stop-Transcript
        }
    }

    if ($installResult) {
        Write-Host "[SUCCESS] Installation Metascript completed successfully."
    }

} catch {
    # This is the outer catch for the Metascript itself
    $errorMessage = "A fatal error occurred in the Installation Metascript: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}