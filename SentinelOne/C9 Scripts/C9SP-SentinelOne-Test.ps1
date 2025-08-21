# =================================================================================
# Name:     C9SP-SentinelOne-Test Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

Import-Module "C9MetascriptHelpers" -Verbose:$false
Import-Module "C9SentinelOneMeta" -Verbose:$false

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
    Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host -ForegroundColor Yellow "[$ScriptName] Reboot complete. Re-gathering fresh system state to ensure accuracy..."
    $script:systemState = Get-C9ComprehensiveSystemState
    
    # We log the new state so we have a clear record of the "before" and "after".
    $formattedStatusAfterReboot = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
    Write-Host "----------------- POST-REBOOT COMPREHENSIVE STATE -----------------"
    Write-Host $formattedStatusAfterReboot
    Write-Host "-----------------------------------------------------------------"
    # The script now continues execution from this point.
} elseif (-not $clearPendingDecision.ShouldProceed) {
    throw "[$ScriptName] HALT: Cannot clear pending reboot safely: $($clearPendingDecision.Reason)"
}
Write-Host "[$ScriptName] Phase 1 Complete. Proceeding to S1 health validation..."

# --- Phase 2: S1 Health Validation (Services-First Logic) ---
Write-Host "`n[$ScriptName] Phase 2: Evaluating SentinelOne agent health with services-first logic..."
$s1Status = $script:systemState.S1Status

# Check if all four core services are present and in a 'Running' state.
$servicesReport = $s1Status.ServicesReport
$runningServices = $servicesReport | Where-Object { $_.Existence -eq 'Exists' -and $_.RunningState -eq 'Running' }

if ($runningServices.Count -eq 4) {
    Write-Host -ForegroundColor Green "[$ScriptName] [PASS] All 4 core SentinelOne services are present and running. The agent is considered healthy."
    # If the services are healthy, we pass the test immediately.
    # The presence of orphaned folders is considered a cleanup task, not a health failure.
    return $true
}

# --- If we are here, the primary service check failed. Now we gather detailed failure reasons. ---
Write-Warning "[$ScriptName] [FAIL] Primary health check failed (found $($runningServices.Count)/4 running services). Gathering detailed failure report..."
$reasonsForFailure = @()

# Analyze services in detail
if ($runningServices.Count -ne 4) {
    $notRunning = $servicesReport | Where-Object { $_.RunningState -ne 'Running' }
    foreach ($service in $notRunning) {
        $reasonsForFailure += "Service '$($service.Service)' is not running (State: $($service.RunningState), Existence: $($service.Existence))."
    }
}

# Now check for other, secondary failure conditions to provide a complete diagnostic picture.
if (-not $s1Status.IsPresentAnywhere) { $reasonsForFailure += "Agent is not present on the system." }

$otherFilesStatus = ($s1Status.InstallDirectoryReport | Where-Object { $_.Property -eq 'Other Child Folder Total Files' }).Value
if ($otherFilesStatus -match '\d+' -and ([int]$otherFilesStatus) -gt 0) {
    # This is a warning/info-level reason, not a primary failure condition.
    $reasonsForFailure += "[INFO] Orphaned files found in other Sentinel directories ($otherFilesStatus files)."
}

$ctlSuccess = ($s1Status.SentinelCtlStatusReport | Where-Object { $_.Property -eq 'Execution Was Successful' }).Value
if (-not $ctlSuccess) { $reasonsForFailure += "sentinelctl.exe status command failed." }

if ($s1Status.VersionFromService -ne $s1Status.VersionFromCtl) {
    $reasonsForFailure += "Version mismatch (Service: $($s1Status.VersionFromService), Ctl: $($s1Status.VersionFromCtl))."
}

Write-Warning "[$ScriptName] [FAIL] The agent is considered UNHEALTHY. Reason(s):"
foreach ($reason in $reasonsForFailure) {
    Write-Warning "- $reason"
}
return $false