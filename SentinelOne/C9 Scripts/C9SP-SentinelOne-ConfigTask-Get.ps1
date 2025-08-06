# =================================================================================
# Name:     C9SP-SentinelOne-ConfigTask-Get Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

#Requires -Version 5.1
<#
.SYNOPSIS
    (GET Script) Retrieves the current health and identity of the SentinelOne agent
    with maximum verbosity for auditing purposes.
.DESCRIPTION
    This script is the "Get" component of a Get/Test/Set configuration task.
    It runs on the endpoint and collects key information about the agent's status,
    providing a detailed step-by-step log in the ImmyBot UI. It returns a simple
    PSCustomObject for the "Test" script to evaluate later.
.NOTES
    Author:     Josh Phillips
    Created:    07/18/2025
    Version:    1.2.0 - Cleaned up final output logging.
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$VerbosePreference = 'Continue'
Write-Host "--- [GET] Starting VERBOSE SentinelOne Agent State Collection ---"

try {
    # Use Invoke-ImmyCommand to execute all logic on the endpoint as SYSTEM.
    $agentState = Invoke-ImmyCommand -ScriptBlock {
        # =========================================================================
        # --- Endpoint SYSTEM Context ---
        # =========================================================================
        
        $VerbosePreference = 'Continue'
        Write-Verbose "--- [ENDPOINT] Starting health audit ---"

        $result = [PSCustomObject]@{
            IsInstalled    = $false
            ServiceState   = 'Not Found'
            AgentId        = $null
            AgentVersion   = $null
        }

        # --- 1. Service Check ---
        Write-Verbose "[1/3] Checking for 'SentinelAgent' service..."
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
        
        if ($service) {
            Write-Verbose "[1/3] SUCCESS: Service found."
            $result.IsInstalled = $true
            $result.ServiceState = $service.State
            Write-Verbose "    - Service State: $($result.ServiceState)"
            
            # --- 2. Version Check ---
            Write-Verbose "[2/3] Checking for Agent Version..."
            if ($service.PathName) {
                $exePath = $service.PathName.Trim('"')
                Write-Verbose "    - Executable path from service: $exePath"
                if (Test-Path -LiteralPath $exePath) {
                    try {
                        $versionInfo = (Get-Item -LiteralPath $exePath).VersionInfo
                        $result.AgentVersion = $versionInfo.ProductVersion
                        Write-Verbose "[2/3] SUCCESS: Found version $($result.AgentVersion)."
                    } catch {
                        Write-Warning "[2/3] FAILED: File exists at '$exePath' but could not get VersionInfo. Error: $_"
                    }
                } else {
                    Write-Warning "[2/3] FAILED: Path '$exePath' from service does not exist on disk."
                }
            } else {
                Write-Warning "[2/3] FAILED: Service found, but PathName property is empty."
            }
        } else {
            Write-Warning "[1/3] FAILED: 'SentinelAgent' service not found. Skipping subsequent checks."
        }

        # --- 3. Agent ID Check ---
        Write-Verbose "[3/3] Checking for Agent ID via SentinelCtl.exe..."
        $ctlPath = (Resolve-Path "C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe" -ErrorAction SilentlyContinue).Path
        if ($ctlPath) {
            Write-Verbose "    - Found SentinelCtl.exe at: $ctlPath"
            try {
                $agentId = (& $ctlPath agent_id 2>$null).Trim()
                if (-not [string]::IsNullOrWhiteSpace($agentId)) {
                    $result.AgentId = $agentId
                    Write-Verbose "[3/3] SUCCESS: Found Agent ID: $($result.AgentId)."
                } else {
                    Write-Warning "[3/3] FAILED: SentinelCtl.exe ran but returned a null or empty Agent ID."
                }
            } catch {
                Write-Warning "[3/3] FAILED: SentinelCtl.exe exists but failed to execute. Error: $_"
            }
        } else {
            Write-Warning "[3/3] FAILED: Could not find SentinelCtl.exe."
        }
        
        Write-Verbose "--- [ENDPOINT] Health audit complete. ---"
        return $result
    }

    # The ImmyBot engine will automatically log the object returned by the script.
    # No need to manually format and write it here.
    Write-Host "[SUCCESS] Agent state collection complete."
    return $agentState

} catch {
    $errorMessage = "A fatal error occurred during the GET operation: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}