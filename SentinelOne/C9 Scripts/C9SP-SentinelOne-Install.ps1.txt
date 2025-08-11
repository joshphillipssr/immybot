# =================================================================================
# Name:     C9SP-SentinelOne-Install Script (Refactored)
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

$VerbosePreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$tempInstallDir = "C:\Temp\S1_Install_$(Get-Random)"

# Import all necessary modules at the start.
Import-Module "C9MetascriptHelpers" -Verbose:$false
Import-Module "C9SentinelOneCloud"  -Verbose:$false
Import-Module "C9SentinelOneMeta"   -Verbose:$false

# Use a single, overarching try/catch/finally for the entire workflow.
try {
    # =========================================================================
    # --- Phase 1: Consolidated Pre-Flight Checks ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 1: Performing consolidated pre-flight system checks..."
    
    Write-Host "[$ScriptName] Checking MSI mutex availability..."       
    Test-C9MsiExecMutex
    Write-Host "[$ScriptName] [PASS] MSI mutex is available."

    Write-Host "[$ScriptName] Checking for any pending reboots that must be cleared..."
    $clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -OverrideSuppression $true -MaxUserIdleMinutes 120
    
    if ($clearPendingDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended: $($clearPendingDecision.Reason)"
        if ($clearPendingDecision.OverrideApplied) { Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied for critical S1 operation." }
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "[$ScriptName] Pre-install reboot completed. The script will now continue with the installation."
    } elseif (-not $clearPendingDecision.ShouldProceed) {
        throw "[$ScriptName] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
    } else {
        Write-Host "[$ScriptName] [PASS] No pending reboot clearance needed."
    }
    Write-Host "[$ScriptName] Phase 1 Complete. Pre-flight checks passed."

    # =========================================================================
    # --- Phase 2: Main Installation (LOGIC RESTORED) ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 2: Staging and executing the MSI installer..."
    $msiPath = (Join-Path -Path $tempInstallDir -ChildPath "SentinelInstaller.msi").Replace('/','\')
    
    # --- Staging Logic ---
    Invoke-ImmyCommand -ScriptBlock {
        $sourceMsi = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelInstaller.msi").FullName
        if (-not (Test-Path $sourceMsi)) {
            throw "[$using:ScriptName] Source MSI not found at $sourceMsi"
        }
        New-Item -ItemType Directory -Path $using:tempInstallDir -Force | Out-Null
        Copy-Item -Path $sourceMsi -Destination $using:msiPath -Force | Out-Null
    }
    Write-Host "[$ScriptName] Installer staged successfully at: $msiPath"

    Write-Host "[$ScriptName] Acquiring Site Token for installation..."
    $siteToken = Get-IntegrationAgentInstallToken
    if ([string]::IsNullOrWhiteSpace($siteToken)) {
        throw "[$ScriptName] Did not receive a valid Site Token."
    }
    
    $msiLogFile = Invoke-ImmyCommand { [IO.Path]::GetTempFileName() }
    Write-Host "[$ScriptName] Generated temporary log file path: $msiLogFile"

    # --- Argument Building ---
    $argumentString = @(
        "/i `"$msiPath`"",
        "/L*v `"$msiLogFile`"", 
        "/qn",
        "/norestart",
        "SITE_TOKEN=$siteToken",
        "WSC=false"
    ) -join ' '

    # --- Execution Logic (Pragmatic Timeout Model) ---
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
            Write-Warning "[$ScriptName] MSI installer timed out as expected. This is part of the workaround. Proceeding to reboot."
        } else {
            throw "[$ScriptName] The installer failed with an unexpected, non-timeout error: $($_.Exception.Message)"
        }
    }
    Write-Host "[$ScriptName] Phase 2 Complete. Main installation action finished."

    # =========================================================================
    # --- Phase 3: Post-Install Reboot ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 3: Evaluating mandatory post-install reboot..."
    $postActionDecision = Test-C9RebootDecision -Scenario PostAction -AllowUserCancel $false
    if ($postActionDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Initiating mandatory post-install reboot: $($postActionDecision.Reason)"
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "[$ScriptName] Post-install reboot complete."
    } else { 
        Write-Warning "[$ScriptName] Unexpected: PostAction scenario did not recommend reboot. This may indicate an issue." 
    }
    Write-Host "[$ScriptName] Phase 3 Complete."

    # =========================================================================
    # --- Phase 4: Final Verification ---
    # =========================================================================
    Write-Host "[$ScriptName] Phase 4: Performing final post-reboot verification..."
    $serviceReport = Get-C9S1ServiceState
    $mainService = $serviceReport | Where-Object { $_.Service -eq 'SentinelAgent' }
    if ($mainService.Existence -eq 'Exists' -and $mainService.RunningState -eq 'Running') {
        Write-Host -ForegroundColor Green "[$ScriptName] [SUCCESS] Final verification passed. The SentinelAgent service is running."
        return $true
    } else {
        throw "Final verification failed. Main SentinelAgent service state is: $($mainService.RunningState) (Existence: $($mainService.Existence))"
    }

} catch {
    $errorMessage = "[$ScriptName] The Installation failed with a fatal error: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
} finally {
    if ($null -ne $tempInstallDir) {
        Write-Host "[$ScriptName] Performing final cleanup of temporary directory: $tempInstallDir"
        Invoke-ImmyCommand -ScriptBlock {
            Remove-Item -Path $using:tempInstallDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}