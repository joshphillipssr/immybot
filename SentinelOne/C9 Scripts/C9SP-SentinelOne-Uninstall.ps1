# =================================================================================
# Name:     C9SP-SentinelOne-Uninstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================
$VerbosePreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# --- Preamble and Parameter Declaration ---
param(
    [string]$RebootPreference
)

# State-tracking variable. It will be set to $true ONLY if we are overriding a 'Suppress' policy.
$forceRebootOverride = $false

# Import all modules needed for the entire script's operation.
Import-Module "C9MetascriptHelpers"
Import-Module "C9SentinelOneMeta"
Import-Module "C9SentinelOneCloud"

# --- Phase 1: Pre-Flight Gatekeeper ---
Write-Host "[$ScriptName] Phase 1: Performing Pre-Flight State Assessment & Safety Gatekeeper..."
$s1AgentState = Get-C9SentinelOneInfo
$rebootWillBeRequired = ($null -ne $s1AgentState.Services)

if ($rebootWillBeRequired) {
    Write-Host "[$ScriptName] [CONDITION] Active S1 services exist. A post-uninstall reboot is mandatory."

    Write-Host "[$ScriptName] Current system reboot policy is: '$RebootPreference'"
    if ($RebootPreference -eq 'Suppress') {
        Write-Host "[$ScriptName] [POLICY] Platform policy is 'Suppress'. Checking for override conditions..."
        if (Test-C9IsUserLoggedIn) {
            throw "[$ScriptName] HALT: A reboot is required, but the platform policy is 'Suppress' and the endpoint is attended. Aborting."
        } else {
            Write-Host "[$ScriptName] [OVERRIDE] Endpoint is unattended. Overriding 'Suppress' policy to proceed with mandatory cleanup."
            # This is the critical state change. We are now in an override state.
            $forceRebootOverride = $true
        }
    } else {
        Write-Host "[$ScriptName] [PASS] Platform reboot policy is '$($RebootPreference)', which permits a required reboot. Proceeding..."
    }
} else {
    Write-Host "[$ScriptName] [CONDITION] No S1 services detected. Proceeding with non-invasive remnant cleanup."
}
Write-Host "[$ScriptName] Phase 1 Complete. Proceeding to main playbook."

# --- Phase 2: Main Uninstallation Playbook ---
try {
    # ... (Trigger file, credential retrieval, etc. - this part of the script remains unchanged)

    Write-Host "[$ScriptName] Checking for uninstall trigger file..."
    $triggerFileDir = "C:\ProgramData\ImmyBot\S1"; $triggerFileName = "s1_is_null.txt"; $newFileName = "s1_isnot_null.txt"
    Invoke-ImmyCommand {
        $triggerFilePath = Join-Path -Path $using:triggerFileDir -ChildPath $using:triggerFileName
        if (Test-Path $triggerFilePath) {
            Write-Host "[$ScriptName] Found uninstall trigger file. Renaming it to break loop."
            try {
                Rename-Item -Path $triggerFilePath -NewName $using:newFileName -ErrorAction Stop
            } catch {
                Write-Warning "Could not rename trigger file."
            }
        }
    }
    
    $Passphrase = $null
    $siteToken = $null

    try {
        Write-Host "[$ScriptName] Attempting to retrieve agent passphrase..."
        $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
        Write-Host "[$ScriptName] Passphrase retrieved successfully."
    } catch {
        Write-Warning "[$ScriptName] Could not retrieve agent passphrase. This is expected for an orphaned agent."
    }

    try {
        Write-Host "[$ScriptName] Attempting to retrieve site token..."
        $siteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
        Write-Host "[$ScriptName] Site token retrieved successfully."
    } catch {
        Write-Warning "[$ScriptName] Could not retrieve site token. The cleaner command may fail."
    }

    # --- Pre-Flight Checks with Override Logic ---
    Write-Host "[$ScriptName] Running inline pre-flight checks..."
    try {
        Test-MsiExecMutex -ErrorAction Stop
        Write-Host "[$ScriptName] [PASS] MSI Mutex is available."
    } catch {
        throw "[$ScriptName] Pre-flight check failed: MSI installation in progress."
    }

    if (Test-PendingReboot) {
        Write-Warning "[$ScriptName] A pending reboot was detected. This must be cleared before proceeding."
        
        # Here we READ the state flag to decide how to reboot.
        if ($forceRebootOverride) {
            Write-Host "[$ScriptName] [OVERRIDE] Forcing pre-flight reboot due to unattended 'Suppress' override."
            try {
                Restart-ComputerAndWait -Force -TimeoutDuration (New-TimeSpan -Minutes 15)
            } catch {
                throw "FATAL: Pre-flight reboot failed. Error: $_"
            }
        } else {
            Write-Host "[$ScriptName] Attempting mandatory pre-flight reboot, respecting platform policy."
            try {
                Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
            } catch {
                throw "FATAL: Pre-flight reboot failed. Error: $_"
            }
        }
        Write-Host "[$ScriptName] SUCCESS: The pre-flight reboot completed."
    } else {
        Write-Host "[$ScriptName] No pending reboot detected."
    }
    Write-Host "[$ScriptName] Pre-flight checks complete."

    # ... (The rest of the uninstallation logic: unprotect, cleaner, etc. remains unchanged) ...

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

    if ($siteToken) {
        Write-Host "[$ScriptName] Site token found. Proceeding to cleaner..."
        $exitCodeFile = "C:\Windows\Temp\s1_uninstall_exit_code.txt"
        Invoke-ImmyCommand -Timeout 1200 -ScriptBlock {
            try {
                if (Test-Path $using:exitCodeFile) {
                    Remove-Item $using:exitCodeFile -Force
                }
                $source = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelOneInstaller*.exe").FullName
                $tempDir = "C:\Temp\S1_Uninstall_$(Get-Date -f yyyyMMdd-hhmmss)"
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                $destination = Join-Path -Path $tempDir -ChildPath (Split-Path $source -Leaf)
                Copy-Item -Path $source -Destination $destination -Force
                $cleanerArgs = "-c -q -t `"$($using:siteToken)`""
                $InstallProcess = Start-Process -NoNewWindow -PassThru -Wait -FilePath $destination -ArgumentList $cleanerArgs
                $LASTEXITCODE | Out-File -FilePath $using:exitCodeFile -Encoding ascii
            } catch {
                "-999" | Out-File -FilePath $using:exitCodeFile -Encoding ascii
                throw
            }
        }
        $cleanerExitCode = Invoke-ImmyCommand {
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

    # --- Phase 3: Post-Uninstall Reboot ---
    if ($rebootWillBeRequired) {
        Write-Host "[$ScriptName] Phase 3: Uninstallation complete. Initiating mandatory reboot."
        if (-not (Test-C9IsUserLoggedIn)) {
            Write-Host "[$ScriptName] Endpoint is unattended. Initiating immediate, forceful reboot."
            Restart-ComputerAndWait -Force -TimeoutDuration (New-TimeSpan -Minutes 15)
        } else {
            Write-Host "[$ScriptName] Endpoint is attended. Delegating reboot decision to platform policy."
            Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        }
    } else {
        Write-Host "[$ScriptName] Phase 3: Remnant cleanup complete. No reboot was required."
    }

    Write-Host "[$ScriptName] Uninstallation Playbook Completed Successfully."
    return $true

} catch {
    $errorMessage = "[$ScriptName] The Uninstallation failed with a fatal error: $($_.Exception.Message)"
    throw $errorMessage
}
    