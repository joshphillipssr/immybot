# =================================================================================
# Name:     C9SP-SentinelOne-Test Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================
# $VerbosePreference = 'Continue'

param([string]$rebootPreference)

$forceNullFlagFile = "C:\ProgramData\ImmyBot\S1\s1_is_null.txt"

if (Test-FilePath -Path $forceNullFlagFile) {
    Write-Host "[$ScriptName] OVERRIDE DETECTED: Found '$forceNullFlagFile'."
    Write-Host "[$ScriptName] Forcing test to return `$false to trigger the UNINSTALL workflow."
    return $false
}

Import-Module "C9MetascriptHelpers"

# --- Pre-Flight System Checks (This logic is excellent and remains unchanged) ---
Write-Host "[$ScriptName] Starting pre-flight system checks..."
try {
    Test-C9MsiExecMutex
    Write-Host "[$ScriptName] [PASS] MSI Mutex is available."
} catch {
    throw "[$ScriptName] Pre-flight check failed: A conflicting MSI installation is in progress."
}
Write-Host "[$ScriptName] [DECISION] Evaluating pending reboot clearance using comprehensive decision logic..."
$clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -OverrideSuppression $true -MaxUserIdleMinutes 120
if ($clearPendingDecision.ShouldReboot) {
    Write-Host "[$ScriptName] [ACTION] Clearing pending reboot as recommended: $($clearPendingDecision.Reason)"
    if ($clearPendingDecision.OverrideApplied) { Write-Host "[$ScriptName] [OVERRIDE] Platform policy override applied for critical S1 operation." }
    try {
        Write-Host "[$ScriptName] Initiating pre-flight reboot (timeout: 15 minutes)..."
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "[$ScriptName] SUCCESS: The pre-flight reboot completed."
    } catch { throw "[$ScriptName] FATAL: Pre-flight reboot was required, but the self-healing attempt was unsuccessful. Error: $_" }
} elseif (-not $clearPendingDecision.ShouldProceed) {
    throw "[$ScriptName] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
} else {
    Write-Host "[$ScriptName] [PASS] No pending reboot clearance needed: $($clearPendingDecision.Reason)"
}

Write-Host "[$ScriptName] Pre-flight checks complete. Proceeding to S1 health validation..."
# --- End of Unchanged Pre-Flight Checks ---


# =====================================================================================
# --- NEW: Comprehensive Health Check using our new Orchestrator Function ---
# =====================================================================================
try {
    Write-Host "[$ScriptName] Starting new Comprehensive Health Check..."

    # Import the modules containing our new functions
    Import-Module "C9SentinelOneMeta" -ErrorAction Stop
    Import-Module "C9MetascriptHelpers" -ErrorAction Stop # For the formatter

    # --- THE GET PHASE ---
    # This is the single call that gets all the data we need.
    $s1Status = Get-C9S1ComprehensiveStatus
    
    # Log the detailed findings for excellent diagnostics.
    # The formatter function will create a clean table from the rich, nested object.
    $formattedStatus = Format-C9ObjectForDisplay -InputObject $s1Status | Format-Table -AutoSize | Out-String
    Write-Host "----------------- COMPREHENSIVE S1 STATUS -----------------"
    Write-Host -ForegroundColor Cyan $formattedStatus
    Write-Host "---------------------------------------------------------"

    # --- THE TEST PHASE ---
    # The decision logic is now beautifully simple. We just check the summary booleans.

    # First, handle the case where the agent isn't present at all.
    # A non-present agent is not "healthy" in the context of this test script. It should fail.
    if (-not $s1Status.IsPresent) {
        Write-Warning "[$ScriptName] [FAIL] Agent is not present on the system."
        return $false
    }
    
    # Now, check the master health status flag. This single property encapsulates all our checks.
    if ($s1Status.IsConsideredHealthy) {
        Write-Host -ForegroundColor Green "[$ScriptName] [PASS] Agent is considered healthy based on comprehensive checks."
        return $true
    }
    else {
        Write-Warning "[$ScriptName] [FAIL] Agent is present but is considered UNHEALTHY."
        # The detailed table logged above will show exactly which check failed.
        return $false
    }

} catch {
    Write-Error "[$ScriptName] The Test Script failed with a fatal error: $($_.Exception.Message)"
    # A fatal error during the test means the state is unknown/unhealthy.
    return $false
}