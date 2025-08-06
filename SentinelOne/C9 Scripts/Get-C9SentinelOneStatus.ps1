<#
.SYNOPSIS
    A Metascript function that retrieves the detailed operational status of the SentinelOne agent from an endpoint.
.DESCRIPTION
    This function is designed to be called from a Metascript context. It uses Invoke-ImmyCommand
    to locate the SentinelCtl.exe utility on the endpoint, execute the 'status' command, and
    then parse the text output into a structured PowerShell object for easy consumption.
    The parsing logic is designed to handle both key-value pairs and simple status lines.
.RETURNS
    [PSCustomObject] A PowerShell object containing key-value pairs from the 'sentinelctl status'
    output. Simple status lines are collected into a 'Status_Messages' array property.
    $null if the agent is not found or if the status command fails.
.EXAMPLE
    $agentStatus = Get-C9SentinelOneStatus
    if ($agentStatus) {
        Write-Host "Self-Protection: $($agentStatus.Self-Protection_status)"
        $agentStatus.Status_Messages | ForEach-Object { Write-Host "Status Message: $_" }
    }
#>
function Get-C9SentinelOneStatus {
    [CmdletBinding()]
    param()

    Write-Host "Attempting to get detailed S1 agent status from the endpoint..."
    
    $statusObject = Invoke-ImmyCommand -ScriptBlock {
        # This entire script block runs on the endpoint as SYSTEM in FullLanguage mode.
        try {
            # Step 1: Find the 'SentinelAgent' service to get the authoritative path.
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
            if (-not $service) { return $null }

            # Step 2: Build the full path to SentinelCtl.exe.
            $installDir = Split-Path -Path ($service.PathName.Trim('"')) -Parent
            $sentinelCtlPath = Join-Path -Path $installDir -ChildPath 'SentinelCtl.exe'
            if (-not (Test-Path -LiteralPath $sentinelCtlPath)) { return $null }

            # Step 3: Execute 'sentinelctl status' and capture its output.
            $statusOutput = & $sentinelCtlPath status

            # Step 4: [REVISED] Intelligent parsing for both line types.
            $parsedStatus = [ordered]@{
                # Initialize an array to hold non-key-value status lines.
                Status_Messages = @()
            }
            foreach ($line in $statusOutput) {
                # Skip any blank lines
                if ([string]::IsNullOrWhiteSpace($line)) { continue }

                # Check if the line is a key-value pair.
                if ($line -like '*:*') {
                    $parts = $line.Split(':', 2)
                    $key = $parts[0].Trim().Replace(' ', '_').Replace(':', '')
                    $value = $parts[1].Trim()
                    $parsedStatus[$key] = $value
                }
                # If it's not a key-value pair, treat it as a general status message.
                else {
                    $parsedStatus['Status_Messages'] += $line.Trim()
                }
            }
            
            # SUCCESS: Return the clean, structured object to the Metascript.
            return [PSCustomObject]$parsedStatus

        } catch {
            Write-Warning "An unexpected error occurred during endpoint status check: $_"
            return $null
        }
    }

    if ($statusObject) {
        Write-Host "Successfully retrieved agent status object."
    } else {
        Write-Host "Could not retrieve a valid status object from the endpoint."
    }

    return $statusObject
}
Get-C9SentinelOneStatus
# Works