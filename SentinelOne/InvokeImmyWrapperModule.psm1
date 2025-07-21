# In C9SentinelOne.psm1

# =================================================================================================
# HELPER/INTERNAL FUNCTIONS
# =================================================================================================

# THIS IS OUR NEW "SMART BRIDGE" FUNCTION
function Invoke-C9S1EndpointCommand {
    [CmdletBinding()]
    param(
        # The command to execute on the endpoint, e.g., "Get-S1AgentId"
        [Parameter(Mandatory)]
        [string]$Command,

        # A hashtable of arguments for the command
        [Parameter()]
        [hashtable]$CommandParameters = @{}
    )

    Write-Verbose "Preparing to execute '$Command' on the remote endpoint."
    try {
        # 1. READ the raw text of our endpoint tools module.
        #    This requires the .psm1 file to be in the same directory as this script.
        $endpointModulePath = Join-Path $PSScriptRoot "C9S1EndpointTools.psm1"
        $endpointModuleContent = Get-Content -Path $endpointModulePath -Raw

        # 2. CONSTRUCT the scriptblock to send over the wire.
        $scriptBlock = {
            param(
                [string]$ModuleContent,
                [string]$CmdToRun,
                [hashtable]$CmdParams
            )

            # A. Create a dynamic module from the text content we passed in.
            #    This makes all functions from C9S1EndpointTools.psm1 available.
            $dynamicModule = New-Module -ScriptBlock ([ScriptBlock]::Create($ModuleContent)) -Name 'C9S1EndpointTools'
            Import-Module $dynamicModule -Force

            Write-Host "Endpoint module loaded. Executing '$CmdToRun'..."

            # B. Execute the desired command with its parameters.
            #    The '&' operator calls the command, and '@' splats the parameters.
            & $CmdToRun @CmdParams
        }

        # 3. EXECUTE the bridge call, passing our module content and commands as arguments.
        return Invoke-ImmyCommand -ScriptBlock $scriptBlock -ArgumentList $endpointModuleContent, $Command, $CommandParameters
    }
    catch {
        Write-Warning "An error occurred in Invoke-C9S1EndpointCommand while trying to run '$Command': $($_.Exception.Message)"
        # Return null on failure so the calling function can handle it.
        return $null
    }
}

function Test-C9S1LocalUpgradeAuthorization {
    # ... This function remains exactly the same as before ...
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AgentId
    )

    $endpoint = "agents/$AgentId/local-upgrade-authorization"
    Write-Verbose "Checking API endpoint '$endpoint' for agent protection status."

    try {
        $response = Invoke-C9S1RestMethod -Endpoint $endpoint
        if ($null -ne $response.enabled -and $response.enabled) {
            Write-Verbose "API Response: Local upgrade authorization is ENABLED."
            return $true
        } else {
            Write-Verbose "API Response: Local upgrade authorization is DISABLED."
            return $false
        }
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            Write-Warning "Agent ID '$AgentId' returned a 404 (Not Found) from the API. This is a ghost agent."
            throw "GHOST_AGENT"
        }
        Write-Warning "An unexpected API error occurred while checking local upgrade authorization: $($_.Exception.Message)"
        return $false
    }
}


# =================================================================================================
# PUBLIC/EXPORTED FUNCTIONS
# =================================================================================================

function Test-S1InstallPreFlight {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Verbose "Starting SentinelOne installation pre-flight check..."

    try {
        # HERE IS THE CHANGE: We now use our generic bridge to call the specific function.
        # We are no longer duplicating the "how to get agent id" logic here.
        $localAgentId = Invoke-C9S1EndpointCommand -Command 'Get-S1AgentId'
        
        if ([string]::IsNullOrWhiteSpace($localAgentId)) {
            return [PSCustomObject]@{
                ShouldStop = $false
                Reason     = 'SentinelOne not detected locally (or Get-S1AgentId failed). Proceeding with installation.'
            }
        }

        Write-Verbose "Successfully retrieved local Agent ID: $localAgentId"

        # The rest of the function is identical to before.
        try {
            $isProtected = Test-C9S1LocalUpgradeAuthorization -AgentId $localAgentId
            if ($isProtected) {
                return [PSCustomObject]@{
                    ShouldStop = $true
                    Reason     = 'STOP: Agent is healthy and protected by a local upgrade/downgrade policy in the S1 portal.'
                }
            }
            else {
                 return [PSCustomObject]@{
                    ShouldStop = $false
                    Reason     = 'Agent is online and not protected by a local upgrade policy. Proceeding with workflow.'
                }
            }
        }
        catch {
            if ($_ -eq 'GHOST_AGENT') {
                return [PSCustomObject]@{
                    ShouldStop = $false
                    Reason     = 'Ghost Agent: Local ID found but does not exist in S1 portal. Proceeding with remediation.'
                }
            }
            throw $_
        }
    }
    catch {
        Write-Warning "An unexpected error occurred during the pre-flight check: $($_.Exception.Message). Defaulting to allow installation."
        return [PSCustomObject]@{
            ShouldStop = $false
            Reason     = "An unexpected error occurred: $($_.Exception.Message). Proceeding with workflow as a failsafe."
        }
    }
}

# Remember to update the Export-ModuleMember list as before.
Export-ModuleMember -Function @(
    'Connect-C9S1API',
    'Invoke-C9S1RestMethod',
    'Get-C9S1Site',
    'Get-C9S1Agent',
    'Test-S1InstallPreFlight'
)