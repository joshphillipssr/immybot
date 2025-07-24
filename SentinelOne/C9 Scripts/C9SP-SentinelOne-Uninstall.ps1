<#
.SYNOPSIS
    Orchestrates the tiered, robust uninstallation of the SentinelOne agent from the Metascript context.
.DESCRIPTION
    This script is the definitive uninstaller for the C9SP-SentinelOne software package. It has been
    re-architected to leverage modern ImmyBot logging and reboot-handling best practices.

    The Metascript now acts as a central orchestrator, executing each phase of the uninstall
    playbook and using platform-native functions for logging and reboot flagging. It uses
    Start-ProcessWithLogTailContext to provide real-time visibility into each removal tool.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    20250722-02 - Final Refactor for Logging & Reboots
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

Write-Host "Importing C9SentinelOne modules..."
Import-Module C9SentinelOneMeta -ErrorAction Stop
Import-Module C9SentinelOneCloud -ErrorAction Stop

# This is our verification check, run from the Metascript.
## Moved to C9SentinelOneMeta.psm1.

Write-Host "Verifying if the SentinelOne agent is still present on the endpoint..."
Test-IsAgentRemoved


# --- SCRIPT EXECUTION STARTS HERE ---

try {
    Write-Host "--- C9-S1 Uninstall Playbook Started ---"

    # Phase 0: Get Passphrase (fault-tolerant)
    $Passphrase = $null
    Write-Verbose "Phase 0: Attempting to retrieve passphrase from integration..."
    try {
        $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($Passphrase)) { throw "Integration returned a null or empty passphrase." }
        Write-Verbose "Successfully retrieved passphrase via integration."
    } catch {
        Write-Warning "Could not retrieve uninstall passphrase. Error: $([string]$_). Proceeding with methods that do not require a passphrase."
    }

    # Phase 0.5: Pre-stage all required removal tools using the platform's native downloader.
    Write-Verbose "Phase 0.5: Downloading required removal tools..."
    $modernCleanerUrl = "https://raw.githubusercontent.com/joshphillipssr/immybot/main/SentinelOne/Tools/SentinelOneInstaller_windows_64bit_v24_2_3_471.exe"
    $legacyCleanerUrl = "https://raw.githubusercontent.com/joshphillipssr/immybot/main/SentinelOne/Tools/SentinelCleaner_22_1GA_64.exe"
    
    $modernCleanerPath = Download-File -Source $modernCleanerUrl
    $legacyCleanerPath = Download-File -Source $legacyCleanerUrl
    Write-Verbose "Tools downloaded successfully to ImmyBot's temp directory."

    # --- THE PLAYBOOK ---
    
    # Phase 1: Modern Cleaner (requires passphrase)
    if (-not [string]::IsNullOrWhiteSpace($Passphrase)) {
        Write-Host "--- Phase 1: Attempting Modern Cleaner (`-c`) ---"
        # Define a log file path for the tool on the endpoint.
        $logPath = "C:\ProgramData\ImmyBot\S1\s1_uninstall_ModernCleaner.log"
        # The Modern Cleaner needs the --log parameter to write to a file.
        $args = @('-c', '-k', $Passphrase, '--qn', '--log', "`"$logPath`"")
        $process = Start-ProcessWithLogTailContext -Path $modernCleanerPath -ArgumentList $args -LogFilePath $logPath -TimeoutSeconds 600
        
        if ($process.ExitCode -eq 0 -and (Test-IsAgentRemoved)) {
            Write-Host "[SUCCESS] Agent successfully removed by Modern Cleaner."
            return
        }
        Write-Warning "Phase 1 did not result in a successful removal. Exit Code: $($process.ExitCode)."
    } else { Write-Warning "--- SKIPPING Phase 1: No passphrase available. ---"}

    # Phase 2: Unprotect Agent (requires passphrase, prepares for legacy cleaner)
    if (-not [string]::IsNullOrWhiteSpace($Passphrase)) {
        Write-Host "--- Phase 2: Attempting to Unprotect Agent (`sentinelctl unprotect`) ---"
        $sentinelCtlPath = Invoke-ImmyCommand {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
            if ($service) { return Join-Path -Path (Split-Path -Path ($service.PathName.Trim('"')) -Parent) -ChildPath 'SentinelCtl.exe' }
            return $null
        }

        if ($sentinelCtlPath) {
            $logPath = "C:\ProgramData\ImmyBot\S1\s1_uninstall_Unprotect.log"
            # SentinelCtl.exe does not have a log flag, but Start-ProcessWithLogTail will capture its console output.
            $args = @('unprotect', '-k', $Passphrase)
            $process = Start-ProcessWithLogTailContext -Path $sentinelCtlPath -ArgumentList $args -LogFilePath $logPath -TimeoutSeconds 300
            
            if ($process.ExitCode -eq 0) { Write-Host "Agent successfully unprotected." } 
            else { Write-Warning "Unprotect command failed. Exit Code: $($process.ExitCode). Proceeding to legacy cleaner anyway."}
        } else { Write-Warning "Could not find SentinelCtl.exe on the endpoint." }
    } else { Write-Warning "--- SKIPPING Phase 2: No passphrase available. ---"}

    # Phase 3: Legacy Cleaner (Nuclear Option)
    Write-Host "--- Phase 3: Attempting Legacy Cleaner ---"
    if(Test-IsAgentRemoved) {
        Write-Host "[SUCCESS] Agent was already removed before Phase 3. Exiting."
        return
    }

    $logPath = "C:\ProgramData\ImmyBot\S1\s1_uninstall_LegacyCleaner.log"
    # The legacy cleaner does not have a log flag, so we tail its console output.
    $process = Start-ProcessWithLogTailContext -Path $legacyCleanerPath -ArgumentList @() -LogFilePath $logPath -TimeoutSeconds 600

    # Verify using the method you discovered: check for the cleaner's own exit code file.
    $cleanerExitCode = Invoke-ImmyCommand { Get-Content -Path 'C:\Windows\Temp\sc-exit-code.txt' -ErrorAction SilentlyContinue }
    if ($cleanerExitCode -eq '0') {
        Write-Host "Legacy Cleaner verification successful (sc-exit-code.txt is 0)."
        
        # REBOOT LOGIC: The cleaner succeeded, so we set the "soft" reboot flag using the platform-native function.
        Write-Host "Setting the pending reboot flag for the OS..."
        Set-PendingRebootFlag
        Write-Warning "A reboot is now pending on this device to finalize the removal."

        if (Test-IsAgentRemoved) {
            Write-Host "[SUCCESS] Agent successfully removed by Legacy Cleaner."
            return
        }
    } else {
         Write-Warning "Legacy Cleaner verification FAILED. Process exit code was $($process.ExitCode), and sc-exit-code.txt reported '$cleanerExitCode' or was not found."
    }

    # Final Verification
    if (Test-IsAgentRemoved) {
        Write-Host "[SUCCESS] Uninstallation Metascript completed successfully after final check."
    } else {
        throw "ALL REMOVAL METHODS FAILED. The agent is still present on the machine."
    }

} catch {
    # This is the final, top-level catch block.
    $errorMessage = "A fatal, unhandled error occurred in the Uninstallation Metascript: $([string]$_)"
    Write-Error $errorMessage
    throw $errorMessage
}