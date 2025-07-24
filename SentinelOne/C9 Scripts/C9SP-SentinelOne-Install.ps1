<#
.SYNOPSIS
    The definitive installation script for the C9SP-SentinelOne software package.
.DESCRIPTION
    This script runs in the Metascript context and follows the definitive architectural pattern
    for an "Installation Script". It leverages the built-in ImmyBot function 'Start-ProcessWithLogTailContext'
    to provide robust, real-time logging of the installer process. This version is streamlined to only
    support modern SentinelOne installers (v22.2+).
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    20250722-02
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

# Pre-flight check
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
    $SiteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($SiteToken)) {
        throw "Get-IntegrationAgentInstallToken did not return a site token. Check integration audit log."
    }
    Write-Verbose "Successfully retrieved site token."

    # Step 2: Build the argument list for the modern installer.
    # We have standardized on modern installers (v22.2+) and no longer include logic for legacy versions.
    # The --log parameter tells the S1 installer to create its own log file, which is then tailed by Start-ProcessWithLogTailContext.
    # The $InstallerLogFile variable is automatically provided by the ImmyBot platform.
    Write-Verbose "Building arguments for modern EXE installer (version $DisplayVersion)..."
    $ArgumentList = "-t `"$SiteToken`" -f --qn --log `"$InstallerLogFile`""

    # Step 3: Announce parameters and invoke the installation using the Immy-approved function.
    # This approach avoids the "Cannot create type" error caused by a conflict between Start-Transcript 
    # and Immy's internal output stream listeners.
    
    Write-Host "--- Installation Parameters ---"
    Write-Host "Installer Path: `"$InstallerFile`""
    Write-Host "Installer Version: $DisplayVersion"
    Write-Host "Log File Path: `"$InstallerLogFile`""
    Write-Host "Full Command: `"$InstallerFile`" $ArgumentList"
    Write-Host "-------------------------------"
    Write-Host "Starting SentinelOne installation. Tailing log file in real-time..."

    # This single call to an Immy-native function handles process execution, the active wait loop,
    # and real-time streaming of the installer's log file to the Immy UI.
    Start-ProcessWithLogTailContext -Path $InstallerFile -ArgumentList $ArgumentList -LogFilePath $InstallerLogFile -TimeoutSeconds 900

    # If the above function completes without throwing an error, the installation is considered successful from a process perspective.
    Write-Host "[SUCCESS] Installation process completed without fatal errors."

} catch {
    # This is the outer catch for the Metascript itself.
    # Casting the error object '$_' to a string is a safe operation in ConstrainedLanguage mode and prevents secondary errors.
    $errorMessage = "A fatal error occurred in the Installation Metascript: $([string]$_)"
    Write-Error $errorMessage
    throw $errorMessage
}