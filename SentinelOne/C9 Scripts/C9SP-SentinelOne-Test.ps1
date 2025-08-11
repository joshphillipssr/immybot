# =================================================================================
# Name:     C9SP-SentinelOne-Test Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

$VerbosePreference = 'Continue'
$DebugPreference = 'Continue'

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

# --- Phase 2: S1 Health Validation ---
# (This logic is unchanged and correct)
Write-Host "`n[$ScriptName] Phase 2: Evaluating SentinelOne agent health..."
$s1Status = $script:systemState.S1Status
$reasonsForFailure = @()
if (-not $s1Status.IsPresentAnywhere) { $reasonsForFailure += "Agent is not present on the system." }
if (-not ($s1Status.ServicesReport -and $s1Status.InstallDirectoryReport -and $s1Status.SentinelCtlStatusReport)) {
    $reasonsForFailure += "One or more critical data reports could not be generated."
} else {
    $mainService = $s1Status.ServicesReport | Where-Object { $_.Service -eq 'SentinelAgent' }
    if ($mainService.Existence -ne 'Exists') { $reasonsForFailure += "Main SentinelAgent service does not exist." }
    elseif ($mainService.RunningState -ne 'Running') { $reasonsForFailure += "Main SentinelAgent service is not running (State: $($mainService.RunningState))." }
    $otherFilesStatus = ($s1Status.InstallDirectoryReport | Where-Object { $_.Property -eq 'Other Child Folder Total Files' }).Value
    if ($otherFilesStatus -match '\d+' -and ([int]$otherFilesStatus) -gt 0) { $reasonsForFailure += "Orphaned files found in other Sentinel directories ($otherFilesStatus files)." }
    $ctlSuccess = ($s1Status.SentinelCtlStatusReport | Where-Object { $_.Property -eq 'Execution Was Successful' }).Value
    if ($ctlSuccess -ne 'True') { $reasonsForFailure += "sentinelctl.exe status command failed." }
    if ($s1Status.VersionFromService -ne $s1Status.VersionFromCtl) { $reasonsForFailure += "Version mismatch (Service: $($s1Status.VersionFromService), Ctl: $($s1Status.VersionFromCtl))." }
}
if ($reasonsForFailure.Count -eq 0) {
    Write-Host -ForegroundColor Green "[$ScriptName] [PASS] All health checks passed."
    return $true
} else {
    Write-Warning "[$ScriptName] [FAIL] The agent is considered UNHEALTHY. Reason(s):"; foreach ($reason in $reasonsForFailure) { Write-Warning "- $reason" }; return $false
}