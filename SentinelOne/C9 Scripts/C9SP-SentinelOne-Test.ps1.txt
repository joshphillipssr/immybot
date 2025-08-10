# =================================================================================
# Name:     C9SP-SentinelOne-Test Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

$VerbosePreference = 'Continue'
$DebugPreference = 'Continue'

$forceNullFlagFile = "C:\ProgramData\ImmyBot\S1\s1_is_null.txt"
if (Test-FilePath -Path $forceNullFlagFile) {
    Write-Host -ForegroundColor DarkYellow "[$ScriptName] OVERRIDE DETECTED: Forcing test to return `$false."
    return $false
}

Import-Module "C9MetascriptHelpers"
Import-Module "C9SentinelOneMeta"

# =========================================================================
# --- Phase 0: The Ultimate Get ---
# =========================================================================

if ($null -eq $script:systemState) {
    $script:systemState = Get-C9ComprehensiveSystemState
} else {
    Write-Host "[$ScriptName] Resuming with persisted system state from before reboot."
}

Start-Sleep -Seconds 5
# --- For diagnostics, let's log the key reports we gathered ---
Write-Host -ForegroundColor DarkYellow "`n--- Top-Level S1 Summary ---" 
$summaryObject = [ordered]@{ "Agent Is Present" = $script:systemState.S1Status.IsPresentAnywhere; "Version (Service)" = $script:systemState.S1Status.VersionFromService; "Version (sentinelctl)"= $script:systemState.S1Status.VersionFromCtl; "Agent ID" = $script:systemState.S1Status.AgentId }; New-Object -TypeName PSObject -Property $summaryObject | Format-List
Start-Sleep -Seconds 5
Write-Host -ForegroundColor DarkYellow "`n--- S1 Install Directory Report ---"
$script:systemState.S1Status.InstallDirectoryReport | Format-Table -AutoSize
Start-Sleep -Seconds 5
Write-Host -ForegroundColor DarkYellow "`n--- S1 Services Report ---"
$script:systemState.S1Status.ServicesReport | Format-Table -AutoSize
Start-Sleep -Seconds 5
Write-Host -ForegroundColor DarkYellow "`n--- Reboot Requirements Report ---"
$script:systemState.RebootRequirements | Format-List

# =========================================================================
# --- Phase 1: Pre-Flight Safety Checks ---
# =========================================================================

Write-Host "`n[$ScriptName] Phase 1: Performing pre-flight safety checks..."
Test-C9MsiExecMutex
$clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -SystemState $script:systemState -OverrideSuppression $true
if ($clearPendingDecision.ShouldReboot) {
    Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended..."
    Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
    throw "[$ScriptName] Halting execution after pre-flight reboot to ensure fresh state analysis on next run."
} elseif (-not $clearPendingDecision.ShouldProceed) {
    throw "[$ScriptName] HALT: Cannot clear pending reboot safely: $($clearPendingDecision.Reason)"
}
Write-Host "[$ScriptName] Phase 1 Complete. Proceeding to S1 health validation..."

# =========================================================================
# --- Phase 2: S1 Health Validation (Corrected Logic) ---
# =========================================================================
Write-Host "`n[$ScriptName] Phase 2: Evaluating SentinelOne agent health..."

# We define our "definition of healthy" as a series of rules.
$s1Status = $script:systemState.S1Status
$reasonsForFailure = @()

# Rule 1: Agent must be present.
if (-not $s1Status.IsPresentAnywhere) { $reasonsForFailure += "Agent is not present on the system." }

# Rule 2: All report objects must exist (prevents errors on very broken installs).
if (-not ($s1Status.ServicesReport -and $s1Status.InstallDirectoryReport -and $s1Status.SentinelCtlStatusReport)) {
    $reasonsForFailure += "One or more critical data reports could not be generated."
} else {
    # Rule 3: Main service must exist and be running. (This now covers the .exe check)
    $mainService = $s1Status.ServicesReport | Where-Object { $_.Service -eq 'SentinelAgent' }
    if ($mainService.Existence -ne 'Exists') {
        $reasonsForFailure += "Main SentinelAgent service does not exist."
    } elseif ($mainService.RunningState -ne 'Running') {
        $reasonsForFailure += "Main SentinelAgent service is not running (State: $($mainService.RunningState))."
    }

    # Rule 4: No orphaned files.
    $otherFilesStatus = ($s1Status.InstallDirectoryReport | Where-Object { $_.Property -eq 'Other Child Folder Total Files' }).Value
    if ($otherFilesStatus -match '\d+' -and ([int]$otherFilesStatus) -gt 0) {
        $reasonsForFailure += "Orphaned files found in other Sentinel directories ($otherFilesStatus files)."
    }

    # Rule 5: sentinelctl must succeed.
    $ctlSuccess = ($s1Status.SentinelCtlStatusReport | Where-Object { $_.Property -eq 'Execution Was Successful' }).Value
    if ($ctlSuccess -ne 'True') { $reasonsForFailure += "sentinelctl.exe status command failed." }
    
    # Rule 6: Versions must match.
    if ($s1Status.VersionFromService -ne $s1Status.VersionFromCtl) { $reasonsForFailure += "Version mismatch (Service: $($s1Status.VersionFromService), Ctl: $($s1Status.VersionFromCtl))." }
}

# --- FINAL DECISION ---
if ($reasonsForFailure.Count -eq 0) {
    Write-Host -ForegroundColor Green "[$ScriptName] [PASS] All health checks passed."
    return $true
}
else {
    Write-Warning "[$ScriptName] [FAIL] The agent is considered UNHEALTHY. Reason(s):"
    foreach ($reason in $reasonsForFailure) { Write-Warning "- $reason" }
    return $false
}