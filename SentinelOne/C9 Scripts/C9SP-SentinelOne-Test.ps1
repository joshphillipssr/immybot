# =================================================================================
# Name:     C9SP-SentinelOne-Test Script (Refactored)
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================
# $VerbosePreference = 'Continue'

param([string]$rebootPreference)

$forceNullFlagFile = "C:\ProgramData\ImmyBot\S1\s1_is_null.txt"

if (Test-FilePath -Path $forceNullFlagFile) {
    Write-Verbose "OVERRIDE DETECTED: Found '$forceNullFlagFile'."
    Write-Verbose "Forcing test to return `$false to trigger the UNINSTALL workflow."
    return $false
}

Import-Module "C9MetascriptHelpers"

# --- Pre-Flight System Checks with New Decision Logic ---
Write-Host "[C9SP-SentinelOne-Test] Starting pre-flight system checks..."

try {
    Test-MsiExecMutex
    Write-Host "[C9SP-SentinelOne-Test] [PASS] MSI Mutex is available."
} catch {
    throw "Pre-flight check failed: A conflicting MSI installation is in progress."
}

# Use our new decision logic for ClearPending scenario
Write-Host "[C9SP-SentinelOne-Test] [DECISION] Evaluating pending reboot clearance using comprehensive decision logic..."
$clearPendingDecision = Test-C9RebootDecision -Scenario ClearPending -OverrideSuppression $true -MaxUserIdleMinutes 120

if ($clearPendingDecision.ShouldReboot) {
    Write-Host "[C9SP-SentinelOne-Test] [ACTION] Clearing pending reboot as recommended: $($clearPendingDecision.Reason)"
    
    if ($clearPendingDecision.OverrideApplied) {
        Write-Host "[C9SP-SentinelOne-Test] [OVERRIDE] Platform policy override applied for critical S1 operation."
    }
    
    try {
        # Delegate to native function - it will handle user interaction based on platform policy
        Write-Host "[C9SP-SentinelOne-Test] Initiating pre-flight reboot (timeout: 15 minutes)..."
        Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)
        Write-Host "[C9SP-SentinelOne-Test] SUCCESS: The pre-flight reboot completed."
    } catch {
        throw "FATAL: Pre-flight reboot was required, but the self-healing attempt was unsuccessful. Error: $_"
    }
} elseif (-not $clearPendingDecision.ShouldProceed) {
    throw "[C9SP-SentinelOne-Test] HALT: Cannot clear pending reboot safely. Reason: $($clearPendingDecision.Reason)"
} else {
    Write-Host "[C9SP-SentinelOne-Test] [PASS] No pending reboot clearance needed: $($clearPendingDecision.Reason)"
}

Write-Host "[C9SP-SentinelOne-Test] Pre-flight checks complete. Proceeding to S1 health validation..."

# --- S1 Health Check Logic (Unchanged) ---
try {
    Write-Host "[C9SP-SentinelOne-Test] Starting Three-Point Health Check..."

    Import-Module "C9SentinelOneMeta" -ErrorAction Stop
    Import-Module "C9MetascriptHelpers" -ErrorAction Stop

    # --- CHECK 1: GET AGENT SERVICE VERSION ---
    Write-Host "[C9SP-SentinelOne-Test] [1/3] Checking version from agent service..."
    $serviceInfo = Get-C9SentinelOneInfo
    $serviceVersion = $serviceInfo.Version
    if ([string]::IsNullOrWhiteSpace($serviceVersion)) {
        Write-Warning "[C9SP-SentinelOne-Test] [FAIL] Could not determine a version from the SentinelAgent service."
        return $false
    }
    Write-Host "[C9SP-SentinelOne-Test] [PASS] Service reports version: $serviceVersion"

    # =========================================================================
    # --- CHECK 2: GET SENTINELCTL VERSION (Corrected Parsing) ---
    # =========================================================================
    Write-Host "[C9SP-SentinelOne-Test] [2/3] Checking version from sentinelctl.exe..."
    
    if (-not $serviceInfo.InstallPath) {
        Write-Warning "[C9SP-SentinelOne-Test] [FAIL] Cannot find agent installation path to run sentinelctl.exe."
        return $false
    }
    $sentinelctlPath = Join-Path -Path $serviceInfo.InstallPath -ChildPath "sentinelctl.exe"
    $sentinelctlResult = Invoke-C9EndpointCommand -FilePath $sentinelctlPath -ArgumentList "status"
    
    if ($sentinelctlResult.ExitCode -ne 0) {
        Write-Warning "[C9SP-SentinelOne-Test] [FAIL] sentinelctl.exe status command failed with exit code: $($sentinelctlResult.ExitCode)."
        return $false
    }

    # --- BEGIN CORRECTED SECTION ---
    $sentinelctlVersion = $null
    
    # First, split the single multi-line output string into an array of lines.
    # This ensures Select-String behaves predictably.
    $outputLines = $sentinelctlResult.StandardOutput -split '(?:\r\n|\r|\n)'

    # Now, find the correct line from the array.
    $versionLine = $outputLines | Select-String -Pattern 'Monitor Build id:'
    
    if ($versionLine) {
        # Line is "Monitor Build id: 24.2.3.471+a12f..."
        $versionStringWithExtras = ($versionLine.ToString() -split ':', 2)[1].Trim()
        $sentinelctlVersion = ($versionStringWithExtras -split '\+', 2)[0].Trim()
    }
    # --- END CORRECTED SECTION ---

    if ([string]::IsNullOrWhiteSpace($sentinelctlVersion)) {
        Write-Warning "[C9SP-SentinelOne-Test] [FAIL] Could not parse a version from the sentinelctl status output."
        return $false
    }
    Write-Host "[C9SP-SentinelOne-Test] [PASS] sentinelctl reports version: $sentinelctlVersion"

    # =========================================================================
    # --- CHECK 3: COMPARE VERSIONS ---
    # =========================================================================
    Write-Host "[C9SP-SentinelOne-Test] [3/3] Comparing versions..."

    if ($serviceVersion -ne $sentinelctlVersion) {
        Write-Warning "[C9SP-SentinelOne-Test] [FAIL] Version Mismatch! Service version is '$serviceVersion', but sentinelctl version is '$sentinelctlVersion'."
        return $false
    }

    Write-Host "[C9SP-SentinelOne-Test] [PASS] Versions match."

    # --- FINAL SUCCESS ---
    Write-Host "[C9SP-SentinelOne-Test] --- All health checks passed. Agent is healthy. ---"
    return $true

} catch {
    Write-Error "[C9SP-SentinelOne-Test] The Test Script failed with a fatal error: $($_.Exception.Message)"
    return $false
}