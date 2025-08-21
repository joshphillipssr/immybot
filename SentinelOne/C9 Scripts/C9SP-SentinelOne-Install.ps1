# =================================================================================
# Name:     C9SP-SentinelOne-Install Script (with Corrected Logic)
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param(
    [string]$rebootPreference,
    [string]$InstallerFile,
    [string]$installerFolder,
    [string]$installerLogFile
)

    # =======================================================================
    #  Load persisted installer variables so that we know where the S1
    #  installer executable resides.  The download script (C9SP-SentinelOne-
    #  DownloadInstaller.ps1) saves these values via Set-C9S1InstallerState.
    #  When this install script runs, $InstallerFile may not be set by the
    #  platform.  In that case we pull from the persisted JSON.  This must be
    #  done before Phase 0 so the path is available when we extract the MSI.
    # =======================================================================
    try {
        $persistedVars = Get-C9S1InstallerState -ErrorAction SilentlyContinue
        if ($persistedVars) {
            $script:installerFolder   = $persistedVars.InstallerFolder
            $script:installerFile    = $persistedVars.InstallerFile
            $script:installerLogFile = $persistedVars.InstallerLogFile
        }
    } catch {
        Write-Warning "[$ScriptName] Unable to load persisted installer state: $($_.Exception.Message)"
    }

    # If the InstallerFile parameter wasn't passed in but we have a persisted
    # installer path, use it.  This prevents attempts to extract from an empty
    # string which would otherwise throw 'The system cannot find the file specified'.
    if ([string]::IsNullOrWhiteSpace($InstallerFile) -and -not [string]::IsNullOrWhiteSpace($script:installerFile)) {
        $InstallerFile = $script:installerFile
    }

$tempInstallDir = "C:\Temp\S1_Install_$(Get-Random)"

# Import all necessary modules at the start.
Import-Module "C9MetascriptHelpers" -Verbose:$false
Import-Module "C9SentinelOneCloud"  -Verbose:$false
Import-Module "C9SentinelOneMeta"   -Verbose:$false

try {
    # --- Phase 0: Initial System State Assessment ---
    if ($null -eq $script:systemState) {
        Write-Host "[$ScriptName] Phase 0: Performing ultimate comprehensive status assessment..."
        $script:systemState = Get-C9ComprehensiveSystemState
        
        $formattedStatus = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
        Write-Host "----------------- COMPREHENSIVE SYSTEM STATE -----------------"
        Write-Host $formattedStatus
        Write-Host "------------------------------------------------------------"
    } else {
        Write-Host -ForegroundColor Yellow "[$ScriptName] Phase 0: Resuming with persisted system state from before reboot."
    }

    # --- Phase 1: Pre-Flight Safety Checks ---
    Write-Host "`n[$ScriptName] Phase 1: Performing pre-flight safety checks..."
    Test-C9MsiExecMutex
    $clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -SystemState $script:systemState -OverrideSuppression $true
    if ($clearPendingDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended..."
        # Capture the result of Restart-ComputerAndWait so we can detect failure
        $rebootResult = Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        if ($null -eq $rebootResult -or $rebootResult -eq $false) {
            throw "[$ScriptName] The reboot did not complete successfully. Aborting installation."
        }
        Write-Host -ForegroundColor Yellow "[$ScriptName] Reboot complete. Re-gathering fresh system state to ensure accuracy..."
        $script:systemState = Get-C9ComprehensiveSystemState

        # Log the new state so we have a clear record of the "before" and "after".
        $formattedStatusAfterReboot = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
        Write-Host "----------------- POST-REBOOT COMPREHENSIVE STATE -----------------"
        Write-Host $formattedStatusAfterReboot
        Write-Host "-----------------------------------------------------------------"
        # Verify that the pending reboot markers were cleared.  If not, stop here.
        if ($script:systemState.RebootRequirements.IsRebootPending) {
            throw "[$ScriptName] Pending reboot conditions remain after reboot; cannot proceed with installation."
        }
    } elseif (-not $clearPendingDecision.ShouldProceed) {
        throw "[$ScriptName] HALT: Cannot clear pending reboot safely: $($clearPendingDecision.Reason)"
    }
    Write-Host "[$ScriptName] Phase 1 Complete. Proceeding to S1 health validation..."


    # =========================================================================
    # --- Phase 2: Main Installation (Existing Logic Preserved) ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 2: Staging and executing the MSI installer..."

    # Step 2a: Extract the MSI from the provided .exe installer.
    # This logic is derived from your ticket notes on 07/30/25.
    $msiPath = (Join-Path -Path $tempInstallDir -ChildPath "SentinelInstaller.msi").Replace('/','\')
        
    Write-Host "[$ScriptName] Acquiring portable 7-Zip utility to extract MSI..."
    $7zaPath = Get-C9Portable7za
    if (-not $7zaPath) {
        throw "Could not acquire the 7za.exe utility."
    }

    # Ensure we have a valid path to the installer executable.  Without this the
    # extraction will fail with "The system cannot find the file specified".
    if ([string]::IsNullOrWhiteSpace($InstallerFile)) {
        throw "[$ScriptName] InstallerFile parameter is empty and no persisted installer file was found. Cannot extract SentinelInstaller.msi."
    }
    Write-Host "[$ScriptName] Extracting 'SentinelInstaller.msi' from '$InstallerFile'..."
    Invoke-ImmyCommand -ScriptBlock {
        # Ensure the temp directory exists on the endpoint
        New-Item -Path $using:tempInstallDir -ItemType Directory -Force | Out-Null
        # Execute 7za on the endpoint to extract the MSI
        & $using:7zaPath x $using:InstallerFile -o$using:tempInstallDir SentinelInstaller.msi | Out-Null
    }

    if (-not (Invoke-ImmyCommand { Test-Path $using:msiPath })) {
        throw "Failed to extract SentinelInstaller.msi from the main installer package."
    }
    Write-Host "[$ScriptName] Installer MSI staged successfully at: $msiPath"

    # Step 2b: Execute the MSI with timeout to solve for race condition
    Write-Host "[$ScriptName] Acquiring Site Token for installation..."
    $siteToken = Get-IntegrationAgentInstallToken
    if ([string]::IsNullOrWhiteSpace($siteToken)) {
        throw "[$ScriptName] Did not receive a valid Site Token."
    }
        
    # We create our own verbose MSI log file.
    $msiLogFile = Join-Path -Path $tempInstallDir -ChildPath "S1_Install_Log.log"

    $argumentString = "/i `"$msiPath`" /L*v `"$msiLogFile`" /qn /norestart SITE_TOKEN=$siteToken WSC=false"

    try {
        Write-Host "[$ScriptName] Executing the installer with a 10-minute timeout..."
        $installProcess = Start-ProcessWithLogTail -Path 'msiexec.exe' -ArgumentList $argumentString -LogFilePath $msiLogFile -TimeoutSeconds 600
            
        if ($null -eq $installProcess) {
            throw "[$ScriptName] Start-ProcessWithLogTail did not return a process object."
        }
            
        Write-Host "[$ScriptName] Installer finished cleanly with Exit Code: $($installProcess.ExitCode)"
        if ($installProcess.ExitCode -ne 0 -and $installProcess.ExitCode -ne 3010) {
            throw "[$ScriptName] Installer failed with an unexpected error code: $($installProcess.ExitCode)."
        }
    }
    catch {
        if ($_.Exception.Message -like "*timed out*") {
                Write-Warning "[$ScriptName] MSI installer timed out as expected. This is the correct handling for the S1 race condition. Proceeding to mandatory reboot."
        } else {
                # Any other error is unexpected and should be fatal.
                throw "[$ScriptName] The installer failed with an unexpected, non-timeout error: $($_.Exception.Message)"
        }
    }
    Write-Host "[$ScriptName] Phase 2 Complete. Main installation action finished."

    # =========================================================================
    # --- Phase 3: Post-Install Reboot (No Changes) ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 3: Evaluating mandatory post-install reboot..."
    $postActionDecision = Test-C9RebootDecision -Scenario PostAction -AllowUserCancel $false
    if ($postActionDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Initiating mandatory post-install reboot: $($postActionDecision.Reason)"
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "[$ScriptName] Post-install reboot complete."
    }
    Write-Host "[$ScriptName] Phase 3 Complete."

    # =========================================================================
    # --- Phase 4: Final Verification & State Persistence (THE ONLY CHANGE IS HERE) ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 4: Performing final post-reboot verification..."
    $s1Status = Get-C9S1ComprehensiveStatus

    if ($s1Status.IsPresentAnywhere -and $s1Status.VersionFromService) {
        Write-Host -ForegroundColor Green "[$ScriptName] [SUCCESS] Final verification passed. Agent version $($s1Status.VersionFromService) is installed and reporting."
        return $true
    } else {
        throw "Final verification failed. The SentinelOne agent was not found or is not reporting a version after installation."
    }

} catch {
    $errorMessage = "[$ScriptName] The Installation failed with a fatal error: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
} finally {
    # Final cleanup of the temporary directory.
    if ($null -ne $tempInstallDir) {
        Write-Host "[$ScriptName] Performing final cleanup of temporary directory: $tempInstallDir"
        Invoke-ImmyCommand -ScriptBlock {
            Remove-Item -Path $using:tempInstallDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}