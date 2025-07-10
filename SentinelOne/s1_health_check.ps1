# S1 Agent Health Check Script
#
# PURPOSE:
# Performs a comprehensive, multi-phase health check. If the agent is healthy, it exits
# cleanly. If any failure is detected, it attempts to remediate. If at any point a condition
# cannot be resolved, the script will log the issue and exit with a failure status.
#
# This entire script block is set to run in the METASCRIPT CONTEXT in the ImmyBot UI.

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

# Define the path for the state file. This must be the same in the Remediation script.
$stateDirectory = 'C:\ProgramData\ImmyBot\State'
$stateFilePath = Join-Path -Path $stateDirectory -ChildPath 'S1_Health.json'

# Use an [ordered] dictionary with the final, logical key order.
$healthState = [ordered]@{
    CheckTimestamp       = (Get-Date).ToString('o') # ISO 8601 format
    AgentUUID            = $null
    Phase1_Services      = 'NOT_RUN'
    Phase2_Registry      = 'NOT_RUN'
    Phase3_Communication = 'NOT_RUN'
    Phase4_API           = 'NOT_RUN'
}

try {
    Write-Verbose "--- S1 Health Check started in METASCRIPT context ---"

    # === PHASE 1 OF 4: SERVICE CHECK ===
    Write-Verbose "[Phase 1] Delegating service check to endpoint SYSTEM context..."
    $healthState['Phase1_Services'] = Invoke-ImmyCommand {
        try {
            $requiredServices = @('SentinelAgent', 'SentinelHelperService', 'SentinelStaticEngine', 'LogProcessorService')
            foreach ($serviceName in $requiredServices) {
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                if ($service.Status -ne 'Running') { return "[FAIL] Service '$serviceName' is not running. State: $($service.Status)." }
            }
            return "[PASS]"
        } catch { return "[FAIL] Service check failed: $($_.Exception.Message)" }
    }
    Write-Verbose "Result: $($healthState['Phase1_Services'])"

    # === PHASE 2 OF 4: PROACTIVE REGISTRY CHECK ===
    # See the following URL for details on the registry check:
    # https://usea1-001-mssp.sentinelone.net/soc-docs/en/services-missing-after-windows-update.html#services-missing-after-windows-update

    Write-Verbose "[Phase 2] Delegating registry check to endpoint SYSTEM context..."
    $healthState['Phase2_Registry'] = Invoke-ImmyCommand {
        try {
            $upgradeCodePath = 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\06BA9B59DEB374C4FA0C5E78A65715A2'
            $productCode = Get-ItemPropertyValue -Path $upgradeCodePath -Name '(Default)' -ErrorAction Stop
            if (-not $productCode) { return "[FAIL] The S1 UpgradeCode registry key value is empty." }
            $productPath = "HKLM:\SOFTWARE\Classes\Installer\Products\$productCode"
            if (-not (Test-Path -Path $productPath)) { return "[FAIL] The S1 ProductCode key '$productCode' is missing." }
            return "[PASS]"
        } catch { return "[FAIL] Registry check failed: $($_.Exception.Message)" }
    }
    Write-Verbose "Result: $($healthState['Phase2_Registry'])"

    # === PHASE 3 OF 4: LOCAL AGENT COMMUNICATION ===
    Write-Verbose "[Phase 3] Delegating local agent communication check to endpoint SYSTEM context..."
    $phase3Result = Invoke-ImmyCommand {
        try {
            $agentPath = (Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'").PathName.Trim('"')
            if (-not $agentPath) { return "[FAIL] Could not determine agent path from service." }
            $sentinelCtlPath = Join-Path -Path (Split-Path -Path $agentPath -Parent) -ChildPath "SentinelCtl.exe"
            if (-not (Test-Path -LiteralPath $sentinelCtlPath)) { return "[FAIL] SentinelCtl.exe not found." }
            $statusResult = . $sentinelCtlPath status
            if (-not (Select-String -InputObject $statusResult -Pattern 'is running' -Quiet)) { return "[FAIL] SentinelCtl status check failed." }
            return (& $sentinelCtlPath agent_id).Trim()
        } catch { return "[FAIL] Agent communication check failed: $($_.Exception.Message)" }
    }
    if ($phase3Result -and -not $phase3Result.StartsWith("[FAIL]") -and $phase3Result.Length -eq 32) {
        $healthState['Phase3_Communication'] = '[PASS]'
        $healthState['AgentUUID'] = $phase3Result
    } else {
        $healthState['Phase3_Communication'] = $phase3Result
    }
    Write-Verbose "Result: $($healthState['Phase3_Communication'])"

    # === PHASE 4 OF 4: S1 API HEALTH CHECK ===
    if ($healthState['AgentUUID']) {
        Write-Verbose "[Phase 4] Querying SentinelOne API for endpoint health..."
        try {
            Import-Module SentinelOne
            Connect-S1API -S1Uri $SentinelOneUri -S1ApiToken $ApiKey | Out-Null
            $query = @{ uuid = $healthState['AgentUUID'] }
            $agentData = Invoke-S1RestMethod -Endpoint 'agents' -QueryParameters $query -ErrorAction Stop
            if (-not $agentData) { $healthState['Phase4_API'] = "[FAIL] API call returned no agent data." }
            elseif ($agentData.isDecommissioned -eq $true) { $healthState['Phase4_API'] = "[FAIL] API reports agent is decommissioned." }
            elseif ($agentData.isActive -ne $true) { $healthState['Phase4_API'] = "[FAIL] API reports agent is inactive." }
            elseif ($agentData.infected -eq $true) { $healthState['Phase4_API'] = "[FAIL] API reports agent is infected." }
            elseif ($agentData.userActionsNeeded -contains 'reboot_needed') { $healthState['Phase4_API'] = "[FAIL] API reports agent requires a reboot." }
            else { $healthState['Phase4_API'] = "[PASS]" }
        } catch { $healthState['Phase4_API'] = "[FAIL] API check failed with an exception: $($_.Exception.Message)" }
    } else {
        $healthState['Phase4_API'] = "[SKIP] Skipped because AgentUUID was not found in Phase 3."
    }
    Write-Verbose "Result: $($healthState['Phase4_API'])"

    # === FINAL VERDICT & CONDITIONAL STATE FILE CREATION ===
    $isHealthy = (-not ($healthState.Values | Where-Object { $_ -is [string] -and $_.StartsWith("[FAIL]") }))

    if ($isHealthy) {
        Write-Verbose "--- ALL HEALTH CHECKS PASSED. Agent is healthy. ---"
        return $true
    } else {
        Write-Verbose "--- ONE OR MORE HEALTH CHECKS FAILED. Writing state file for parsing by remediation script. ---"
        $jsonData = $healthState | ConvertTo-Json -Depth 5
        Invoke-ImmyCommand -ErrorAction Stop -ScriptBlock {
            if (-not (Test-Path -Path $using:stateDirectory)) {
                New-Item -Path $using:stateDirectory -ItemType Directory -Force | Out-Null
            }
            Set-Content -Path $using:stateFilePath -Value $using:jsonData -Encoding utf8 -Force
        }
        Write-Verbose "Successfully wrote health state to $stateFilePath on the endpoint."
        return $null
    }
}
catch {
    Write-Error "A fatal, unrecoverable error occurred: $($_.Exception.Message)"
    $healthState['FatalError'] = $_.Exception.Message
    $jsonData = $healthState | ConvertTo-Json -Depth 5
    Invoke-ImmyCommand -ErrorAction SilentlyContinue -ScriptBlock {
        if (-not (Test-Path -Path $using:stateDirectory)) { New-Item -Path $using:stateDirectory -ItemType Directory -Force | Out-Null }
        Set-Content -Path $using:stateFilePath -Value $using:jsonData -Encoding utf8 -Force
    }
    return $null
}
