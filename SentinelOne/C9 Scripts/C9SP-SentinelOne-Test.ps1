# =================================================================================
# Name:     C9SP-SentinelOne-Test Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

$forceNullFlagFile = "C:\ProgramData\ImmyBot\S1\s1_is_null.txt"
if (Test-FilePath -Path $forceNullFlagFile) {
    Write-Host "[$ScriptName] OVERRIDE DETECTED: Forcing test to return `$false."
    return $false
}

Import-Module "C9MetascriptHelpers"
Import-Module "C9SentinelOneMeta"

# =========================================================================
# --- Phase 0: Ultimate Comprehensive Status Assessment ---
# =========================================================================
# This script now gathers ALL state data upfront, just like the Uninstall script.
# This ensures consistency and prevents redundant data gathering calls.
if ($null -eq $script:systemState) {
    Write-Host "[$ScriptName] Phase 0: Performing ultimate comprehensive status assessment..."
    
    $script:systemState = New-Object -TypeName PSObject
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'S1Status' -Value (Get-C9S1ComprehensiveStatus)
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'RebootPolicy' -Value (Get-C9RebootPolicyContext)
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'UserActivity' -Value (Get-C9UserActivityStatus)
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'RebootRequirements' -Value (Get-C9SystemRebootRequirements)

    $formattedStatus = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
    Write-Host "----------------- COMPREHENSIVE SYSTEM STATE -----------------"
    Write-Host $formattedStatus -ForegroundColor Cyan 
    Write-Host "------------------------------------------------------------"

    Write-Host "[$ScriptName] Phase 0 Complete. System state has been captured."
} else {
    Write-Host "[$ScriptName] Phase 0: Resuming with persisted system state from before reboot."
}

# =========================================================================
# --- Phase 1: Pre-Flight Safety Checks ---
# =========================================================================
Write-Host "[$ScriptName] Phase 1: Performing pre-flight safety checks..."
try {
    Test-C9MsiExecMutex
    Write-Host "[$ScriptName] [PASS] MSI Mutex is available."
} catch {
    throw "[$ScriptName] Pre-flight check failed: A conflicting MSI installation is in progress."
}

# --- This decision logic now uses the pre-gathered state ---
Write-Host "[$ScriptName] [DECISION] Evaluating pending reboot clearance using comprehensive decision logic..."
$clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -SystemState $script:systemState -OverrideSuppression $true

if ($clearPendingDecision.ShouldReboot) {
    Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended: $($clearPendingDecision.Reason)"
    Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
    $script:systemState = $null # Invalidate state to force re-check on next run
    throw "Halting execution after pre-flight reboot to ensure fresh state analysis on next run."
} elseif (-not $clearPendingDecision.ShouldProceed) {
    throw "[$ScriptName] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
} else {
    Write-Host "[$ScriptName] [PASS] No pending reboot clearance needed: $($clearPendingDecision.Reason)"
}
Write-Host "[$ScriptName] Phase 1 Complete. Proceeding to S1 health validation..."

# =========================================================================
# --- Phase 2: S1 Health Validation ---
# =========================================================================
try {
    Write-Host "[$ScriptName] Phase 2: Evaluating SentinelOne agent health..."

    # The decision logic is now beautifully simple and reads from the state object.
    if (-not $script:systemState.S1Status.IsPresentAnywhere) {
        Write-Warning "[$ScriptName] [FAIL] Agent is not present on the system."
        return $false
    }
    
    if ($script:systemState.S1Status.IsConsideredHealthy) {
        Write-Host -ForegroundColor Green "[$ScriptName] [PASS] Agent is considered healthy based on comprehensive checks."
        return $true
    }
    else {
        Write-Warning "[$ScriptName] [FAIL] Agent is present but is considered UNHEALTHY."
        # The detailed table logged in Phase 0 shows exactly which check failed.
        return $false
    }

} catch {
    Write-Error "[$ScriptName] The Test Script failed with a fatal error: $($_.Exception.Message)"
    # A fatal error during the test means the state is unknown/unhealthy.
    return $false
}