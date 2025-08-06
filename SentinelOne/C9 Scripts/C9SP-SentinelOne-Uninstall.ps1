# =================================================================================
# Name:     C9SP-SentinelOne-Uninstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

# --- Preamble and Parameter Declaration ---
param(
    [string]$rebootPreference
)

$tempUninstallDir = $null

# $VerbosePreference = 'Continue'
# $ProgressPreference = 'SilentlyContinue'

# Import all modules needed for the entire script's operation.
Import-Module "C9MetascriptHelpers"
Import-Module "C9SentinelOneMeta"
Import-Module "C9SentinelOneCloud"

# --- Phase 1: Pre-Flight Gatekeeper ---
Write-Host "[$ScriptName] Phase 1: Performing Pre-Flight State Assessment & Safety Gatekeeper..."
$s1AgentState = Get-C9SentinelOneInfo
$rebootWillBeRequired = ($null -ne $s1AgentState.Service)

if ($rebootWillBeRequired) {
    Write-Host "[$ScriptName] Active S1 Windows Services exist. A post-uninstall reboot is mandatory and will be required..."
    Write-Host "[$ScriptName] Will now perform a comprehensive pre-action safety evaluation to determine if ..."
    
    # Use our new decision logic for PreAction scenario
    Write-Host "[$ScriptName] [DECISION] Evaluating pre-action safety using comprehensive decision logic..."
    $preActionDecision = Test-C9RebootDecision -Scenario PreAction -OverrideSuppression $true -MaxUserIdleMinutes 120
    
    if (-not $preActionDecision.ShouldProceed) {
        throw "[$ScriptName] HALT: Cannot proceed with S1 uninstall. Reason: $($preActionDecision.Reason)"
    }
    
    Write-Host -ForegroundColor Green "[$ScriptName] Pre-action evaluation complete: $($preActionDecision.Reason)"
    if ($preActionDecision.OverrideApplied) {
        Write-Host "[$ScriptName] [OVERRIDE] Platform policy override was applied for critical S1 operation."
    }
} else {
    Write-Host "[$ScriptName] [CONDITION] No S1 services detected. Proceeding with non-invasive remnant cleanup."
}
Write-Host "[$ScriptName] Phase 1 Complete. Proceeding to uninstall playbook."

# --- Phase 2: Main Uninstallation Playbook ---
try {
    # Trigger file, credential retrieval, etc. - this part of the script remains unchanged
    Write-Host "[$ScriptName] Checking for uninstall trigger file..."
    $triggerFileDir = "C:\ProgramData\ImmyBot\S1"; $triggerFileName = "s1_is_null.txt"; $newFileName = "s1_isnot_null.txt"
    Invoke-ImmyCommand {
        $triggerFilePath = Join-Path -Path $using:triggerFileDir -ChildPath $using:triggerFileName
        if (Test-Path $triggerFilePath) {
            Write-Host "[$using:ScriptName] Found uninstall trigger file. Renaming it to break loop..."
            try {
                Rename-Item -Path $triggerFilePath -NewName $using:newFileName -ErrorAction Stop
                Write-Host "[$using:ScriptName] Trigger file renamed successfully. Continuing with uninstallation..."
            } catch {
                Write-Warning "[$using:ScriptName] Could not rename trigger file."
            }
        }
    }
    
    $Passphrase = $null
    $siteToken = $null

    # Try block for retrieving passphrase
    try {
        Write-Host "[$ScriptName] Attempting to retrieve agent passphrase..."
        $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
        Write-Host "[$ScriptName] Passphrase retrieved successfully."
    } catch {
        Write-Warning "[$ScriptName] Could not retrieve agent passphrase. This is expected for an orphaned agent."
    }

    # Try block for retrieving site token
    try {
        Write-Host "[$ScriptName] Attempting to retrieve site token..."
        $siteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
        Write-Host "[$ScriptName] Site token retrieved successfully."
    } catch {
        Write-Warning "[$ScriptName] Could not retrieve site token. The cleaner command may fail."
    }

    # pre-flight MsiExec check
    Write-Host "[$ScriptName] Running inline pre-uninstallation checks..."
    try {
        Test-MsiExecMutex -ErrorAction Stop
        Write-Host "[$ScriptName] MSI Mutex is available. Safe to proceed with uninstallation..."
    } catch {
        throw "[$ScriptName] Pre-flight check failed: MSI installation in progress."
    }

    # pre-flight reboot clearance
    Write-Host "[$ScriptName] [DECISION] Evaluating pending reboot clearance using comprehensive decision logic..."
    $clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -OverrideSuppression $true -MaxUserIdleMinutes 120
    
    if ($clearPendingDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended: $($clearPendingDecision.Reason)"
        
        if ($clearPendingDecision.OverrideApplied) {
            Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied for critical S1 operation."
        }
        
        try {
            # Delegate to native function - it will handle user interaction based on platform policy
            Write-Host "[$ScriptName] Initiating pre-flight reboot (timeout: 15 minutes)..."
            Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
            Write-Host "[$ScriptName] SUCCESS: The pre-flight reboot completed."
        } catch {
            throw "FATAL: Pre-flight reboot failed. Error: $_"
        }
    } elseif (-not $clearPendingDecision.ShouldProceed) {
        throw "[$ScriptName] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
    } else {
        Write-Host "[$ScriptName] [PASS] No pending reboot clearance needed: $($clearPendingDecision.Reason)"
    }
    
    Write-Host "[$ScriptName] Pre-flight checks complete."

    # if passphrase found - S1 Unprotect and Cleaner execution
    if ($Passphrase) {
        Write-Host "[$ScriptName] Passphrase found. Attempting 'sentinelctl.exe unprotect'..."
        try {
            $s1Info = Get-C9SentinelOneInfo
            if ($s1Info.InstallPath) {
                Set-C9SentinelOneUnprotect -Passphrase $Passphrase -ErrorAction Stop
                Write-Host "[$ScriptName] Self-protection disabled successfully."
            } else {
                Write-Warning "[$ScriptName] sentinelctl.exe not found. Skipping unprotect."
            }
        } catch {
            Write-Warning "[$ScriptName] Failed to disable self-protection. This may be okay. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "[$ScriptName] No passphrase found. Skipping unprotect step."
    }

    # if site token found - run the cleaner
    if ($siteToken) {
        Write-Host "[$ScriptName] Site token found. Proceeding to cleaner..."
        $exitCodeFile = "C:\Windows\Temp\s1_uninstall_exit_code.txt"
    
        # Generate temp directory name and store it for cleanup
        $tempUninstallDir = "C:\Temp\S1_Uninstall_$(Get-Date -f yyyyMMdd-hhmmss)"
    
        Invoke-ImmyCommand -Computer $Computer -Timeout 1200 -ScriptBlock {
            try {
                if (Test-Path $using:exitCodeFile) {
                    Remove-Item $using:exitCodeFile -Force
                }
                $source = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelOneInstaller*.exe").FullName
                New-Item -ItemType Directory -Path $using:tempUninstallDir -Force | Out-Null
                $destination = Join-Path -Path $using:tempUninstallDir -ChildPath (Split-Path $source -Leaf)
                Copy-Item -Path $source -Destination $destination -Force
                $cleanerArgs = "-c -q -t `"$($using:siteToken)`""
                $InstallProcess = Start-Process -NoNewWindow -PassThru -Wait -FilePath $destination -ArgumentList $cleanerArgs
                $LASTEXITCODE | Out-File -FilePath $using:exitCodeFile -Encoding ascii
            } catch {
                "-999" | Out-File -FilePath $using:exitCodeFile -Encoding ascii
                throw
            }
        }
    
        $cleanerExitCode = Invoke-ImmyCommand -Computer $Computer -ScriptBlock {
            if (Test-Path $using:exitCodeFile) {
                Get-Content $using:exitCodeFile
            } else {
                return -1
            }
        }
        Write-Host "[$ScriptName] Cleaner process finished with Exit Code: $cleanerExitCode"
    } else {
        Write-Warning "[$ScriptName] SKIPPED: The modern cleaner method requires a site token."
    }

    # Post-Uninstall Reboot
    if ($rebootWillBeRequired) {
        Write-Host "[$ScriptName] Phase 3: Uninstallation complete. Evaluating mandatory post-action reboot..."
        
        # new decision logic for PostAction scenario
        $postActionDecision = Test-C9RebootDecision -Scenario PostAction -AllowUserCancel $false -MaxUserIdleMinutes 120
        
        Write-Host "[$ScriptName] [DECISION] Post-action evaluation: $($postActionDecision.Reason)"
        
        if ($postActionDecision.ShouldReboot) {
            if ($postActionDecision.OverrideApplied) {
                Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied - S1 changes mandate reboot completion."
            }
            
            Write-Host "[$ScriptName] [ACTION] Initiating mandatory post-uninstall reboot..."
            Write-Host "[$ScriptName] User interaction mode: $($postActionDecision.UserInteractionMode)"
            
            try {
                # Delegate to native function - it will handle user interaction appropriately
                Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
                Write-Host "[$ScriptName] SUCCESS: Post-uninstall reboot completed."
            } catch {
                throw "FATAL: Post-uninstall reboot failed. Error: $_"
            }
        } else {
            Write-Warning "[$ScriptName] Unexpected: PostAction scenario did not recommend reboot. This may indicate an issue."
        }
    } else {
        Write-Host "[$ScriptName] Phase 3: Remnant cleanup complete. No reboot was required."
    }

    Write-Host "[$ScriptName] Uninstallation Playbook Completed Successfully."
    return $true

} catch {
    $errorMessage = "[$ScriptName] The Uninstallation failed with a fatal error: $($_.Exception.Message)"
    throw $errorMessage
} finally {
    # Cleanup temporary uninstall directory if it was created
    if ($null -ne $tempUninstallDir) {
        Write-Host "[$ScriptName] Performing final cleanup of temporary uninstall directory: $tempUninstallDir"
        try {
            Invoke-ImmyCommand -Computer $Computer -ScriptBlock {
                if (Test-Path $using:tempUninstallDir) {
                    Write-Host "[$using:ScriptName] Removing temporary uninstall directory: $using:tempUninstallDir"
                    Remove-Item -Path $using:tempUninstallDir -Recurse -Force -ErrorAction SilentlyContinue
                    
                    # Verify cleanup
                    if (Test-Path $using:tempUninstallDir) {
                        Write-Warning "[$using:ScriptName] Uninstall directory still exists after cleanup attempt"
                    } else {
                        Write-Host "[$using:ScriptName] Temporary uninstall directory cleanup completed successfully"
                    }
                }
            }
        } catch {
            Write-Warning "[$ScriptName] Non-critical error during uninstall cleanup: $($_.Exception.Message)"
        }
    }
}