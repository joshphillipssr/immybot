<#
.SYNOPSIS
    Orchestrates the tiered, robust uninstallation of the SentinelOne agent from the Metascript context.
.DESCRIPTION
    This script is the definitive uninstaller for the C9SP-SentinelOne software package.
    It follows a multi-phase playbook, escalating its removal methods to handle healthy, broken,
    and "ghost" agent installations. It leverages custom helper modules and platform-native
    functions for maximum reliability and observability.
.NOTES
    Author:     Josh Phillips, in collaboration with AI Assistant
    Version:    20250724-1.1 (Refactored downloader function into helper module)
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
$s1UnpackDir = $null

# --- Main Orchestration Block ---
try {
    Write-Host "--- C9-S1 Uninstall Playbook Started ---"

    # --- Setup and Module Imports ---
    Write-Host "Importing helper modules..."
    try {
        # This import now makes BOTH Invoke-C9EndpointCommand and Resolve-InstallerAvailable available.
        Import-Module "C9MetascriptHelpers" -ErrorAction Stop
        Import-Module "C9SentinelOneMeta" -ErrorAction Stop
        Write-Host "Successfully imported helper modules."
    }
    catch {
        throw "Failed to import a required module. Ensure C9MetascriptHelpers and C9SentinelOneMeta are saved as Global Scripts. Error: $_"
    }

    # --- Passphrase Retrieval ---
    $Passphrase = $null
    Write-Host "Attempting to retrieve passphrase from integration..."
    try {
        $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($Passphrase)) { throw "Integration returned a null or empty passphrase." }
        Write-Host "Successfully retrieved agent-specific passphrase."
    } catch {
        Write-Warning "Could not retrieve uninstall passphrase. Some removal methods will be skipped. Error: $($_.Exception.Message)."
    }

    # =========================================================================
    # --- PHASE 1: PRE-FLIGHT SAFETY CHECK ---
    # =========================================================================
  Write-Host "[PHASE 1] Checking for other active MSI installations..."
    try { Test-MsiExecMutex -ErrorAction Stop; Write-Host "[PHASE 1] SUCCESS" }
    catch { throw "[PHASE 1] FAILED: Another MSI installation is in progress. Halting to prevent conflicts." }

    Write-Host "[PHASE 2] Attempting standard, graceful uninstallation..."
    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info) { Write-Host "[SUCCESS] Agent not found on pre-check."; return }

    if ($s1Info -and $Passphrase) {
        $uninstallExe = Join-Path -Path $s1Info.InstallPath -ChildPath "uninstall.exe"
        $logFile = Invoke-ImmyCommand { Join-Path $env:TEMP "s1_uninstall_standard_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" }
        Write-Host "Running standard uninstaller: '$($uninstallExe)'..."
        $uninstallResult = Start-ProcessWithLogTail -Path $uninstallExe -ArgumentList @('/uninstall', '/norestart', '/q', '/k', $Passphrase) -LogFilePath $logFile
        if (-not (Get-C9SentinelOneInfo)) { Write-Host "[SUCCESS] PHASE 2 was successful."; return }
    } else { Write-Warning "[PHASE 2] SKIPPED: Agent info or passphrase not available." }

    Write-Host "[PHASE 3] Agent still present. Attempting to disable self-protection..."
    if ($Passphrase) {
        try { Set-C9SentinelOneUnprotect -Passphrase $Passphrase -ErrorAction Stop }
        catch { Write-Warning "[PHASE 3] FAILED to disable self-protection. This may not be critical." }
    } else { Write-Warning "[PHASE 3] SKIPPED: No passphrase available." }

    Write-Host "[PHASE 4] Attempting removal with the modern installer's clean function..."
    if ($Passphrase -and (Test-Path $InstallerFile)) {
        $logFile = Invoke-ImmyCommand { Join-Path $env:TEMP "s1_uninstall_modern_$(Get-Date -Format 'yyyyMMdd-HHmmss').log" }
        Write-Host "Running modern cleaner using main installer: '$($InstallerFile)'..."
        $cleanerResult = Start-ProcessWithLogTail -Path $InstallerFile -ArgumentList @('-c', '-k', $Passphrase, '--qn', '--log', $logFile) -LogFilePath $logFile
        if (-not (Get-C9SentinelOneInfo)) { Write-Host "[SUCCESS] PHASE 4 was successful."; return }
    } else { Write-Warning "[PHASE 4] SKIPPED: Passphrase or main installer file not available." }


    # =========================================================================
    # --- PHASE 5: THE NUCLEAR OPTION (On-Demand Extraction) ---
    # =========================================================================
    Write-Host "[PHASE 5] Standard methods failed. Escalating to on-demand cleaner extraction..."
    if (Test-Path $InstallerFile) {
        
        # Step 5.1: Locate the 7-Zip CLI executable on the endpoint.
        Write-Host "[PHASE 5.1] Locating 7z.exe from dependent package..."
        $sevenZipPath = Invoke-ImmyCommand -ScriptBlock {
            @(
                "$($env:ProgramFiles)\7-Zip\7z.exe",
                "$($env:ProgramFilesX86)\7-Zip\7z.exe"
            ) | Where-Object { Test-Path $_ } | Select-Object -First 1
        }
        if (-not $sevenZipPath) {
            throw "[PHASE 5.1] FAILED: 7z.exe not found. Ensure '7-Zip' is a dependency for this package."
        }
        Write-Host "[PHASE 5.1] SUCCESS: Found 7-Zip at '$($sevenZipPath)'"

        ### REFACTORED: Use the system temp directory ###
        # Step 5.2: Create a temporary directory for extraction and get its path.
        Write-Host "[PHASE 5.2] Creating temporary unpack directory in endpoint's TEMP folder..."
        $unpackDirPath = Invoke-ImmyCommand -ScriptBlock {
            # Construct the path using the endpoint's environment variables.
            $tempDir = Join-Path -Path $env:TEMP -ChildPath 'ImmyBot_S1_Unpack'
            if (Test-Path $tempDir) {
                # Clean up from any previous failed runs.
                Remove-Item -Path $tempDir -Recurse -Force
            }
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
            # Return the full path back to the Metascript.
            return $tempDir
        }
        Write-Host "[PHASE 5.2] SUCCESS: Created unpack directory at '$($unpackDirPath)'"
        
        # Step 5.3: Extract the cleaner
        Write-Host "[PHASE 5.3] Extracting SentinelCleaner.exe from main installer..."
        $extractionArgs = "e", "`"$InstallerFile`"", "-o`"$unpackDirPath`"", "SentinelCleaner.exe", "-y"
        $extractionResult = Invoke-C9EndpointCommand -FilePath $sevenZipPath -ArgumentList $extractionArgs
        
        $extractedCleanerPath = Join-Path -Path $unpackDirPath -ChildPath "SentinelCleaner.exe"
        if ($extractionResult.ExitCode -ne 0 -or -not (Invoke-ImmyCommand { Test-Path $using:extractedCleanerPath }) ) {
            throw "[PHASE 5.3] FAILED to extract SentinelCleaner.exe. 7-Zip exit code: $($extractionResult.ExitCode). Error: $($extractionResult.StandardError)"
        }
        Write-Host "[PHASE 5.3] SUCCESS: Extracted cleaner to '$($extractedCleanerPath)'"

        # Step 5.4: Run the extracted cleaner
        Write-Host "[PHASE 5.4] Running extracted legacy cleaner..."
        $exitCodeFile = "C:\Windows\Temp\sc-exit-code.txt"
        Invoke-ImmyCommand { if (Test-Path $using:exitCodeFile) { Remove-Item $using:exitCodeFile -Force } }
        $nuclearResult = Invoke-C9EndpointCommand -FilePath $extractedCleanerPath
        $cleanerExitCode = Invoke-ImmyCommand { if (Test-Path $using:exitCodeFile) { return (Get-Content $using:exitCodeFile) } else { return -1 } }
        
        if ($cleanerExitCode -eq '0') {
            Write-Host "[SUCCESS] PHASE 5 appears successful based on status file."
        } else {
            Write-Warning "[PHASE 5] FAILED: Extracted cleaner did not report a successful exit code."
        }
    } else {
        Write-Warning "[PHASE 5] SKIPPED: Main installer file ($InstallerFile) not available for extraction."
    }
    
    # =========================================================================
    # --- PHASE 6 & 7 (Reboot and Final Verification) ---
    # =========================================================================
    # (These phases remain unchanged)
    Write-Host "[PHASE 6] One or more aggressive removal methods were used. A reboot is recommended."
    try {
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "Reboot completed. Proceeding with final verification."
    } catch { throw "[PHASE 6] FAILED: The managed reboot process failed. Error: $_" }

    Write-Host "[PHASE 7] Performing final verification of agent removal..."
    if (-not (Get-C9SentinelOneInfo)) {
        Write-Host "[SUCCESS] Uninstallation Playbook Completed. The SentinelOne agent has been successfully removed."
    } else {
        throw "[FINAL FAILURE] All automated removal methods have failed. The agent is still present on the machine."
    }

} catch {
    # This is the master catch block for the entire playbook.
    $errorMessage = "The Uninstallation Playbook failed with a fatal error: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
} finally {
    # This block runs regardless of success or failure, ensuring we clean up our temporary files.
    # It now uses the dynamic $unpackDirPath variable.
    if ($null -ne $unpackDirPath) {
        Write-Host "--- Performing final cleanup of temporary unpack directory ---"
        Invoke-ImmyCommand -ScriptBlock {
            if (Test-Path $using:unpackDirPath) {
                Write-Host "Removing temporary unpack directory: $($using:unpackDirPath)"
                Remove-Item -Path $using:unpackDirPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}