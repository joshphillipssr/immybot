# =================================================================================
# Name:     C9SP-SentinelOne-Uninstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param(
    [string]$rebootPreference
)

$tempUninstallDir = $null

# Import all modules needed for the entire script's operation.
Import-Module "C9MetascriptHelpers"
Import-Module "C9SentinelOneMeta"
Import-Module "C9SentinelOneCloud"

# =========================================================================
# --- Phase 0: Ultimate Comprehensive Status Assessment ---
# =========================================================================
# If the state object doesn't exist (first run), gather ALL data.
# This object is stored in the script: scope, so it WILL persist across reboots.
if ($null -eq $script:systemState) {
    Write-Host "[$ScriptName] Phase 0: Performing ultimate comprehensive status assessment (S1, Cloud, System, User)..."
    
    # Use ConstrainedLanguage-safe object creation for maximum reliability.
    $script:systemState = New-Object -TypeName PSObject
    
    # --- Add S1-Specific Status ---
    $s1Status = Get-C9S1ComprehensiveStatus
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'S1Status' -Value $s1Status
    
    # --- Add Cloud Credential Status ---
    $passphrase = Get-IntegrationAgentUninstallToken -ErrorAction SilentlyContinue
    $siteToken = Get-IntegrationAgentInstallToken -ErrorAction SilentlyContinue
    $cloudCreds = [ordered]@{
        Passphrase    = $passphrase
        SiteToken     = $siteToken
        HasPassphrase = ($null -ne $passphrase)
        HasSiteToken  = ($null -ne $siteToken)
    }
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'CloudCredentials' -Value (New-Object -TypeName PSObject -Property $cloudCreds)

    # --- Add General System & User Status ---
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'RebootPolicy' -Value (Get-C9RebootPolicyContext)
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'UserActivity' -Value (Get-C9UserActivityStatus)
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'RebootRequirements' -Value (Get-C9SystemRebootRequirements)

    # Log the detailed findings for excellent diagnostics.
    $formattedStatus = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
    Write-Host "----------------- COMPREHENSIVE SYSTEM STATE -----------------"
    Write-Host  $formattedStatus -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------"

    Write-Host "[$ScriptName] Phase 0 Complete. System state has been captured."
} else {
    Write-Host "[$ScriptName] Phase 0: Resuming with persisted system state from before reboot."
}

# Determine early if a reboot will be mandatory post-uninstall.
$rebootWillBeRequired = $script:systemState.S1Status.IsPresentAnywhere

# =========================================================================
# --- Phase 1: Intelligent Playbook Selection ---
# =========================================================================
Write-Host "[$ScriptName] Phase 1: Selecting uninstall playbook based on agent and system status..."

$playbook = "None" 

if (-not $script:systemState.S1Status.IsPresentAnywhere) {
    $playbook = "RemnantCleanup"
    Write-Host "[$ScriptName] [PLAYBOOK: Remnant Cleanup] No agent detected."
} elseif ($script:systemState.S1Status.IsConsideredHealthy -and $script:systemState.CloudCredentials.HasPassphrase) {
    $playbook = "StandardUninstall"
    Write-Host "[$ScriptName] [PLAYBOOK: Standard Uninstall] Agent is healthy and managed. Will perform graceful removal."
} else {
    $playbook = "ForcedRemoval"
    Write-Host "[$ScriptName] [PLAYBOOK: Forced Removal] Agent is unhealthy or orphaned. Will attempt aggressive removal."
}
Write-Host "[$ScriptName] Phase 1 Complete. Proceeding with playbook: $playbook"

# =========================================================================
# --- Phase 2: Execute Uninstallation Playbook ---
# =========================================================================
try {
    # --- Common pre-flight logic ---
    $triggerFileDir = "C:\ProgramData\ImmyBot\S1"; #... (trigger file logic unchanged)
    Invoke-ImmyCommand {
        $triggerFilePath = Join-Path -Path $using:triggerFileDir -ChildPath "s1_is_null.txt"
        if (Test-Path $triggerFilePath) {
            Rename-Item -Path $triggerFilePath -NewName "s1_isnot_null.txt" -ErrorAction SilentlyContinue
        }
    }
    Test-C9MsiExecMutex
    
    # --- Use the pre-gathered state for the reboot decision ---
    $clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -SystemState $script:systemState -OverrideSuppression $true
    
    if ($clearPendingDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Clearing pending reboot before uninstall..."
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        $script:systemState = $null # Invalidate state to force re-check
        throw "Halting execution after pre-flight reboot to ensure fresh state analysis on next run."
    } elseif (-not $clearPendingDecision.ShouldProceed) {
        throw "[$ScriptName] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
    }
    
    # --- Execute the selected playbook ---
    switch ($playbook) {
        "RemnantCleanup" {
            Write-Host "[$ScriptName] Executing Remnant Cleanup. No invasive actions needed."
        }
        "StandardUninstall" {
            Write-Host "[$ScriptName] Executing Standard Uninstall. Attempting 'sentinelctl.exe unprotect'..."
            Set-C9SentinelOneUnprotect -Passphrase $script:systemState.CloudCredentials.Passphrase
        }
        "ForcedRemoval" {
            Write-Host "[$ScriptName] Executing Forced Removal..."
            if ($script:systemState.CloudCredentials.HasPassphrase -and $script:systemState.S1Status.InstallFolderState.SentinelCtlExists -and $script:systemState.S1Status.SentinelCtlStatus.IsHealthy) {
                Write-Host "[$ScriptName] Attempting best-effort 'sentinelctl.exe unprotect'..."
                try {
                    Set-C9SentinelOneUnprotect -Passphrase $script:systemState.CloudCredentials.Passphrase
                } catch {
                    Write-Warning "Best-effort unprotect failed. Continuing..."
                }
            } else {
                Write-Warning "[$ScriptName] Skipping unprotect step (no passphrase, or sentinelctl.exe is missing/unhealthy)."
            }
        }
    }

    # --- Core cleaner execution ---
    if ($playbook -ne "RemnantCleanup") {
        if ($script:systemState.CloudCredentials.HasSiteToken) {
            Write-Host "[$ScriptName] Site token found. Proceeding with modern cleaner..."
            $exitCodeFile = "C:\Windows\Temp\s1_uninstall_exit_code.txt"
            $tempUninstallDir = "C:\Temp\S1_Uninstall_$(Get-Date -f yyyyMMdd-hhmmss)"
    
            Invoke-ImmyCommand -Timeout 1200 -ScriptBlock {
                $source = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelOneInstaller*.exe").FullName
                New-Item -ItemType Directory -Path $using:tempUninstallDir -Force | Out-Null
                $destination = Join-Path -Path $using:tempUninstallDir -ChildPath (Split-Path $source -Leaf)
                Copy-Item -Path $source -Destination $destination -Force
                $cleanerArgs = "-c -q -t `"$($using:script.systemState.CloudCredentials.SiteToken)`"" # Use persisted token
                $InstallProcess = Start-Process -NoNewWindow -PassThru -Wait -FilePath $destination -ArgumentList $cleanerArgs
                $LASTEXITCODE | Out-File -FilePath $using:exitCodeFile -Encoding ascii
            }
            $cleanerExitCode = Get-Content -Path $exitCodeFile
            Write-Host "[$ScriptName] Cleaner process finished with Exit Code: $cleanerExitCode"
        } else {
            Write-Warning "[$ScriptName] SKIPPED: The modern cleaner method requires a site token."
        }
    }

    # =========================================================================
    # --- Phase 3: Post-Uninstall Reboot ---
    # =========================================================================
    if ($rebootWillBeRequired) {
        Write-Host "[$ScriptName] Phase 3: Evaluating mandatory post-action reboot..."
        
        # We MUST refresh user activity right before the final reboot decision.
        # The user could have logged on during the uninstall process.
        $script:systemState.UserActivity = Get-C9UserActivityStatus

        # --- Use the pre-gathered state for the final reboot decision ---
        $postActionDecision = Test-C9RebootDecision -Scenario PostAction -SystemState $script:systemState -AllowUserCancel $false
        
        Write-Host "[$ScriptName] [DECISION] Post-action evaluation: $($postActionDecision.Reason)"
        
        if ($postActionDecision.ShouldReboot) {
            Write-Host "[$ScriptName] [ACTION] Initiating mandatory post-uninstall reboot..."
            Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        }
    } else {
        Write-Host "[$ScriptName] Phase 3: Remnant cleanup complete. No reboot was required."
    }

    Write-Host "[$ScriptName] Uninstallation Playbook Completed Successfully."
    return $true

} catch {
    throw "[$ScriptName] The Uninstallation failed with a fatal error: $($_.Exception.Message)"
} finally {
    if ($null -ne $tempUninstallDir) {
        Write-Host "[$ScriptName] Performing final cleanup of temporary directory: $tempUninstallDir"
        Invoke-ImmyCommand {
            Remove-Item -Path $using:tempUninstallDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}