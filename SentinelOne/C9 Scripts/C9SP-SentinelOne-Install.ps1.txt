# =================================================================================
# Name:     C9SP-SentinelOne-Install Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

# $VerbosePreference = 'Continue'
# $ProgressPreference = 'SilentlyContinue'

$tempInstallDir = "C:\Temp\S1_Install_$(Get-Random)"

Import-Module "C9MetascriptHelpers"

# --- Pre-Flight Safety Assessment ---
Write-Host "[$ScriptName] Evaluating endpoint safety for S1 installation using comprehensive decision logic..."
$preActionDecision = Test-C9RebootDecision -Scenario PreAction -OverrideSuppression $true -MaxUserIdleMinutes 120

if (-not $preActionDecision.ShouldProceed) {
    Write-Warning "[$ScriptName] HALT: Endpoint is not safe for S1 installation."
    Write-Warning "[$ScriptName] Reason: $($preActionDecision.Reason)"
    Write-Warning "[$ScriptName] Recommended Action: $($preActionDecision.RecommendedAction)"
    return $false
}

Write-Host "[$ScriptName] [PASS] Pre-action safety evaluation: $($preActionDecision.Reason)"
if ($preActionDecision.OverrideApplied) {
    Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied for critical S1 operation."
}

# If the PreAction scenario determined we need to clear a critical pending reboot first
if ($preActionDecision.ShouldReboot) {
    Write-Host "[$ScriptName] [ACTION] Clearing critical pending reboot before installation: $($preActionDecision.Reason)"
    
    try {
        Write-Host "[$ScriptName] Initiating pre-installation reboot (timeout: 15 minutes)..."
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "[$ScriptName] SUCCESS: Pre-installation reboot completed."
    } catch {
        throw "[$ScriptName] FATAL: Pre-installation reboot failed. Error: $_"
    }
}

Write-Host "[$ScriptName] Proceeding with SentinelOne installation..."

# --- Module Import and Setup ---
Write-Host "[$ScriptName] Importing required modules..."
Import-Module "C9SentinelOneCloud"
Import-Module "C9SentinelOneMeta"
Write-Host "[$ScriptName] Modules imported successfully."

# --- Pre-Install System Checks ---
Write-Host "[$ScriptName] Performing comprehensive pre-install checks..."    

try {
    Write-Host "[$ScriptName] Checking MSI mutex availability..."       
    Test-C9MsiExecMutex
    Write-Host "[$ScriptName] [PASS] MSI mutex is available."
    
    # Use our new decision logic for ClearPending scenario
    Write-Host "[$ScriptName] [DECISION] Evaluating pending reboot clearance using comprehensive decision logic..."
    $clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -OverrideSuppression $true -MaxUserIdleMinutes 120
    
    if ($clearPendingDecision.ShouldReboot) {
        Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended: $($clearPendingDecision.Reason)"
        
        if ($clearPendingDecision.OverrideApplied) {
            Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied for critical S1 operation."
        }
        
        try {
            Write-Host "[$ScriptName] Initiating pre-install reboot (timeout: 15 minutes)..."
            Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
            Write-Host "[$ScriptName] And...we're back. The pre-install reboot completed. Now we can continue..."
        } catch {
            throw "[$ScriptName] FATAL: Pre-install reboot failed. Error: $_"
        }
    } elseif (-not $clearPendingDecision.ShouldProceed) {
        throw "[$ScriptName] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
    } else {
        Write-Host "[$ScriptName] [PASS] No pending reboot clearance needed: $($clearPendingDecision.Reason)"
    }
    
    Write-Host "[$ScriptName] Pre-install checks complete. Let's get started on the good stuff..."

    # --- MSI Installation Process (Unchanged) ---
    Write-Host "[$ScriptName] Staging the MSI installer in a temporary directory..."
    $msiPath = (Join-Path -Path $tempInstallDir -ChildPath "SentinelInstaller.msi").Replace('/','\')
    Invoke-ImmyCommand -ScriptBlock {
        $sourceMsi = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelInstaller.msi").FullName
        if (-not (Test-Path $sourceMsi)) {
            throw "[$using:ScriptName] Source MSI not found at $sourceMsi"
        }
        New-Item -ItemType Directory -Path $using:tempInstallDir -Force | Out-Null
        Copy-Item -Path $sourceMsi -Destination $using:msiPath -Force
    }
    Write-Host "[$ScriptName] Installer staged successfully at: $msiPath"

    Write-Host "[$ScriptName] We're gonna need a Site Token. Let's make an API call to get it..."
    $siteToken = Get-IntegrationAgentInstallToken
    if ([string]::IsNullOrWhiteSpace($siteToken)) {
        throw "[$ScriptName] Did not receive a valid Site Token."
    }
    Write-Host "[$ScriptName] Got the Site Token. Now let's generate a temp log file path..."
    $msiLogFile = Invoke-ImmyCommand {
        [IO.Path]::GetTempFileName()
    }
    Write-Host "[$ScriptName] Generated temporary log file path: $msiLogFile"

    $argumentString = @(
        "/i `"$msiPath`"",
        "/L `"$msiLogFile`"", 
        "/qn",
        "/norestart",
        "SITE_TOKEN=$siteToken",
        "WSC=false"
    ) -join ' '

    try {
        Write-Host "[$ScriptName] Executing the install. There is a high probability that a race condition"
        Write-Host "[$ScriptName] will cause S1 to invoke protection mode before all the S1 Services"
        Write-Host "[$ScriptName] can start, so we're going to kill this install routine in"
        Write-Host "[$ScriptName] 10 minutes if it hasn't already exited. In the mean time"
        Write-Host "[$ScriptName] sit back and relax and watch this log file go nuts for a while."
        $installProcess = Start-ProcessWithLogTail -Path 'msiexec.exe' -ArgumentList $argumentString -LogFilePath $msiLogFile -TimeoutSeconds 600
        
        if ($null -eq $installProcess) {
            throw "[$ScriptName] Start-ProcessWithLogTail did not return a process object."
        }
        $installExitCode = $installProcess.ExitCode
        Write-Host "[$ScriptName] This is a bit shocking...the installer finished cleanly with Exit Code: $installExitCode"
        if ($installExitCode -ne 0 -and $installExitCode -ne 3010) {
            throw "[$ScriptName] Darn it...installer failed with an unexpected error code: $installExitCode. See logs for details."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -like "*timed out*") {
            Write-Warning "[$ScriptName] Well, as expected, the MSI installer timed out, likely because some S1 Services"
            Write-Warning "[$ScriptName] kept trying to restart over and over and over again."
            Write-Warning "[$ScriptName] This is part of the workaround. We've exited the script cleanly."
        } else {
            throw "[$ScriptName] This sucks. The installer failed with an unexpected, non-timeout (not initiated by us) error: $errorMessage"
        }
    }
    
    # --- Post-Install Reboot with New Decision Logic ---
    Write-Host "[$ScriptName] Installation complete. Evaluating mandatory post-install reboot..."
    
    # Use our new decision logic for PostAction scenario
    $postActionDecision = Test-C9RebootDecision -Scenario PostAction -AllowUserCancel $false -MaxUserIdleMinutes 120
    
    Write-Host "[$ScriptName] [DECISION] Post-action evaluation: $($postActionDecision.Reason)"
    
    if ($postActionDecision.ShouldReboot) {
        if ($postActionDecision.OverrideApplied) {
            Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied - S1 installation mandates reboot completion."
        }
        
        Write-Host "[$ScriptName] [ACTION] Initiating mandatory post-install reboot..."
        Write-Host "[$ScriptName] User interaction mode: $($postActionDecision.UserInteractionMode)"
        
        try {
            Write-Host "[$ScriptName] Now we're going to reboot so the S1 Services can start up like they're supposed to. Back in a min..."
            # Delegate to native function - it will handle user interaction appropriately
            Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
            Write-Host "[$ScriptName] We're back."
        } catch {
            throw "[$ScriptName] NO!!! Post-install reboot was required, but the self-healing attempt was unsuccessful. Error: $_"
        }
    } else {
        Write-Warning "[$ScriptName] Unexpected: PostAction scenario did not recommend reboot. This may indicate an issue."
    }

    # --- Post-Reboot Verification (Unchanged) ---
    Write-Host "[$ScriptName] We're back. Let's start some post-install checks..."
    Write-Host "[$ScriptName] Let's check and see if everything looks good..."
    $s1Info = Get-C9SentinelOneInfo
    if ($s1Info -and $s1Info.IsServiceRunning) {
        Write-Host "[$ScriptName] Success. SentinelOne Agent Service is present and running. Boom."
        Write-Host "[$ScriptName] If we got here, everything worked so we're going to return `$true and get outta here!"
        Write-Host "[$ScriptName] See ya!"
        return $true
    } else {
        throw "[$ScriptName] Final verification failed. The agent service was not found or is not running post-reboot. Bleh."
    }

} catch {
    $errorMessage = "[$ScriptName] The Installation failed with a fatal error: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw "[$ScriptName] HALT: Pre-install check failed. Reason: $($_.Exception.Message)"
} finally {
    if ($null -ne $tempInstallDir) {
        Write-Host "[$ScriptName] Performing final cleanup of temporary directory: $tempInstallDir"
        try {
            Invoke-ImmyCommand -Computer $Computer -ScriptBlock {
                if (Test-Path $using:tempInstallDir) {
                    Write-Host "[$using:ScriptName] Removing temporary directory: $using:tempInstallDir"
                    Remove-Item -Path $using:tempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
                    
                    # Verify cleanup
                    if (Test-Path $using:tempInstallDir) {
                        Write-Warning "[$using:ScriptName] Directory still exists after cleanup attempt"
                    } else {
                        Write-Host "[$using:ScriptName] Temporary directory cleanup completed successfully"
                    }
                }
            }
        } catch {
            Write-Warning "[$ScriptName] Non-critical error during cleanup: $($_.Exception.Message)"
        }
    }
}