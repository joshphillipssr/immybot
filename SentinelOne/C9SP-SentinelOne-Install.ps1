#Requires -Version 5.1
<#
.SYNOPSIS
    The definitive installation script for the C9SP-SentinelOne software package.
.DESCRIPTION
    This script runs in the Metascript context and follows the definitive architectural pattern
    for an "Installation Script":
    1. Manually calls the Get-IntegrationAgentInstallToken cmdlet. The ImmyBot framework
       translates this call, executes the integration's -GetTenantInstallToken capability,
       and returns the site-specific registration token.
    2. Builds the correct command-line arguments for a modern EXE installer.
    3. Uses Invoke-ImmyCommand to execute the installer on the endpoint as SYSTEM.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    4.2.0 - Replaced /LOG with stdout/stderr stream capture for robust logging.
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

try {
    Write-Verbose "--- C9-S1 Installation Metascript Started ---"

    # Step 1: Get the site-specific installation token by calling the correct built-in cmdlet.
    Write-Verbose "Calling Get-IntegrationAgentInstallToken to retrieve site token..."
    $SiteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($SiteToken)) { throw "Get-IntegrationAgentInstallToken did not return a site token. Check integration audit log." }
    Write-Verbose "Successfully retrieved site token."

    # Step 2: Build the argument list for a modern EXE installer.
    $ArgumentList = ''
    Write-Verbose "Building arguments for modern EXE installer version $DisplayVersion..."
    # The $DisplayVersion variable is automatically provided in this context.
    switch -regex ($DisplayVersion) {
        '^22\.1' {
            Write-Verbose "Version is 22.1. Using mandatory --dont_fail_on_config_preserving_failures flag."
            $ArgumentList = "--dont_fail_on_config_preserving_failures -t $SiteToken -f --qn"
        }
        default { # For all newer versions (22.2+).
            Write-Verbose "Version is 22.2 or newer. Using modern arguments."
            $ArgumentList = "-t $SiteToken -f --qn"
        }
    }
    Write-Host "Final argument list constructed: $ArgumentList"

    # Step 3: Invoke the installation command on the endpoint.
    Write-Host "Invoking installer on the endpoint..."
    $result = Invoke-ImmyCommand -ScriptBlock {
        # The installer and arguments are passed in from the Metascript.
        $InstallerPath = $using:InstallerFile
        $InstallerArgs = $using:ArgumentList
        $stdoutLog = Join-Path $env:TEMP "s1_stdout_log.txt"
        $stderrLog = Join-Path $env:TEMP "s1_stderr_log.txt"

        try {
            Write-Host "Executing: `"$InstallerPath`" $InstallerArgs"
            # Execute the installer and redirect its console output streams to our own log files.
            $process = Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
            
            if ($process.ExitCode -in @(0, 3010)) {
                Write-Host "Installation appears successful (Exit Code: $($process.ExitCode))."
                return $true
            } else {
                throw "Installation failed with exit code: $($process.ExitCode)."
            }
        } catch {
            # --- MODIFIED CATCH BLOCK ---
            # On failure, read the captured output streams and include them in the error.
            $originalError = $_.Exception.Message
            $stdoutContents = "Standard Output log not found or was empty at `"$stdoutLog`"."
            $stderrContents = "Standard Error log not found or was empty at `"$stderrLog`"."

            if (Test-Path $stdoutLog) {
                $rawContent = Get-Content -Path $stdoutLog -Raw -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($rawContent)) { $stdoutContents = $rawContent }
            }
            if (Test-Path $stderrLog) {
                $rawContent = Get-Content -Path $stderrLog -Raw -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($rawContent)) { $stderrContents = $rawContent }
            }
            
            # Construct a detailed, multi-line error message to throw back to the ImmyBot console.
            $detailedErrorMessage = @"
A fatal error occurred during installation on the endpoint.
Original Error: $originalError

--- Installer Standard Output (stdout) ---
$stdoutContents

--- Installer Standard Error (stderr) ---
$stderrContents
"@
            throw $detailedErrorMessage
        }
    }

    if ($result) { Write-Host "[SUCCESS] Installation Metascript completed successfully." }

} catch {
    $errorMessage = "A fatal error occurred in the Installation Metascript: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}