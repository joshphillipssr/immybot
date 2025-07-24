# SentinelOne Meta Module
# These functions are primarily used for SentinelOne Metascript to System Context interactions.
# ==============================================================
# Some key ImmyBot Metascript functions to facilitate Metascript to System Context communication are:
#
# Invoke-ImmyCommand - The default wrapper to run commands from the Metascript context on the endpoint System Context.
# Start-ProcessWithLogTail and Start-ProcessWithLogTailContext - Built to solve the inherent of Start-Process and piping log output back to the Metascript context.
# Restart-ComputerAndWait
# 

function Get-C9SentinelOneInfo {
<#
.SYNOPSIS
    Gathers comprehensive information about the local SentinelOne agent installation.
.DESCRIPTION
    A Metascript function that queries the endpoint in the SYSTEM context to find the SentinelOne agent.
    It returns a rich PSCustomObject containing details like version, paths, and service status.
    If the agent is not found, the function returns $null.
.OUTPUTS
    A PSCustomObject containing agent information, or $null if the agent is not found.
    The object includes:
    - IsInstalled ($true)
    - Version (string)
    - Service (CimInstance object)
    - InstallPath (string)
    - AgentExePath (string)
    - SentinelCtlPath (string)
.EXAMPLE
    $s1Info = Get-C9SentinelOneInfo
    if ($s1Info) {
        Write-Host "SentinelOne Version $($s1Info.Version) found at $($s1Info.InstallPath)"
    } else {
        Write-Error "SentinelOne agent not found."
    }
#>
    [CmdletBinding()]
    param()

    Write-Verbose "Querying endpoint for SentinelOne agent information..."

    # This single Invoke-ImmyCommand call gathers all info from the endpoint in one go.
    $infoObject = Invoke-ImmyCommand -ScriptBlock {

        # This logic is based on the proven detection script pattern.
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

        # If the service doesn't exist, the agent is not installed. Return $null.
        if (-not ($service -and $service.PathName)) {
            Write-Warning "SentinelAgent service not found on endpoint. Agent is not installed."
            return $null
        }

        # If the service exists, proceed to gather more details.
        $agentExePath = $service.PathName.Trim('"')
        $installPath = Split-Path -Path $agentExePath
        $sentinelCtlPath = Join-Path -Path $installPath -ChildPath "sentinelctl.exe"

        # Final validation: Ensure the paths reported by the service actually exist.
        if (-not (Test-Path -LiteralPath $agentExePath)) {
            Write-Error "Service found, but its executable path is invalid: $agentExePath"
            return $null
        }

        if (-not (Test-Path -LiteralPath $sentinelCtlPath)) {
            Write-Error "Agent found, but sentinelctl.exe is missing from its directory: $sentinelCtlPath"
            # We can still return info, but log the error. The caller can decide how to handle a missing ctl tool.
        }

        # Get version info from the executable's metadata.
        $fileInfo = Get-Item -LiteralPath $agentExePath
        $version = $fileInfo.VersionInfo.ProductVersion

        # Construct and return the rich object with all collected data.
        return [PSCustomObject]@{
            IsInstalled     = $true
            Version         = $version
            Service         = $service
            InstallPath     = $installPath
            AgentExePath    = $agentExePath
            SentinelCtlPath = $sentinelCtlPath
        }

    }

    # Log the outcome and return the object (or $null) to the calling script.
    if ($infoObject) {
        Write-Host "Successfully retrieved SentinelOne agent info. Version: $($infoObject.Version)"
    } else {
        Write-Warning "Get-C9SentinelOneInfo did not find a valid agent installation on the endpoint."
    }
    
    return $infoObject
}

function Get-C9S1LocalAgentId {
    [CmdletBinding()]
    param()

    Write-Verbose "Attempting to retrieve SentinelOne Agent ID from the local endpoint."
    try {
        # This scriptblock runs on the endpoint as SYSTEM.
        # It's self-contained and has one job: get the agent ID.
        $result = Invoke-ImmyCommand -ScriptBlock {
            # Use Resolve-Path for robustly finding the executable
            $sentinelCtlPath = Resolve-Path "C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe" -ErrorAction SilentlyContinue
            if (-not $sentinelCtlPath) {
                Write-Warning "SentinelCtl.exe not found on the endpoint."
                # Return null explicitly if the exe isn't found
                return $null
            }
            
            # Execute the command to get the agent ID.
            # We trim to ensure no leading/trailing whitespace.
            $agentId = (& $sentinelCtlPath.Path agent_id).Trim()
            return $agentId
        }

        if ([string]::IsNullOrWhiteSpace($result)) {
            Write-Verbose "No local Agent ID was found."
            return $null
        }

        Write-Verbose "Successfully retrieved local Agent ID: $result"
        return $result
    }
    catch {
        Write-Warning "An error occurred while trying to retrieve the local Agent ID: $($_.Exception.Message)"
        return $null
    }
}

function Test-C9S1LocalUpgradeAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AgentId
    )

    $endpoint = "agents/$AgentId/local-upgrade-authorization"
    Write-Verbose "Checking API endpoint '$endpoint' for agent protection status."

    try {
        # We expect a successful call to return data with an 'enabled' property.
        $response = Invoke-C9S1RestMethod -Endpoint $endpoint
        
        # The API returns { "data": { "enabled": true/false } } on success
        if ($null -ne $response.enabled -and $response.enabled) {
            Write-Verbose "API Response: Local upgrade authorization is ENABLED."
            return $true
        }
        else {
            Write-Verbose "API Response: Local upgrade authorization is DISABLED."
            return $false
        }
    }
    catch {
        # Check if the error is specifically a 404 Not Found, which indicates a ghost agent.
        if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            Write-Warning "Agent ID '$AgentId' returned a 404 (Not Found) from the API. This is a ghost agent."
            # We throw a specific string that the calling function can catch and interpret.
            throw "GHOST_AGENT"
        }
        
        # For any other API error, we log it and assume it's not protected as a failsafe.
        Write-Warning "An unexpected API error occurred while checking local upgrade authorization: $($_.Exception.Message)"
        return $false
    }
}

function Test-S1InstallPreFlight {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Verbose "Starting SentinelOne installation pre-flight check..."

    try {
        # Step 1: Get the local agent ID using our dedicated bridge function.
        $localAgentId = Get-C9S1LocalAgentId
        
        # Step 2: Handle the "Not Installed" case. If no ID, we can proceed.
        if (-not $localAgentId) {
            return [PSCustomObject]@{
                ShouldStop = $false
                Reason     = 'SentinelOne not detected locally. Proceeding with installation.'
            }
        }

        # Step 3: We have an ID. Now check its status against the API.
        try {
            $isProtected = Test-C9S1LocalUpgradeAuthorization -AgentId $localAgentId

            # Step 4a: If protected, we MUST stop.
            if ($isProtected) {
                return [PSCustomObject]@{
                    ShouldStop = $true
                    Reason     = 'STOP: Agent is healthy and protected by a local upgrade/downgrade policy in the S1 portal.'
                }
            }
            # Step 4b: If not protected, we can proceed.
            else {
                 return [PSCustomObject]@{
                    ShouldStop = $false
                    Reason     = 'Agent is online and not protected by a local upgrade policy. Proceeding with workflow.'
                }
            }
        }
        catch {
            # Step 4c: Catch the specific "GHOST_AGENT" error from our helper function. This is a "go" condition.
            if ($_ -eq 'GHOST_AGENT') {
                return [PSCustomObject]@{
                    ShouldStop = $false
                    Reason     = 'Ghost Agent: Local ID found but does not exist in S1 portal. Proceeding with remediation.'
                }
            }
            # If it was a different, unexpected error, re-throw it to be caught by the outer block.
            throw $_
        }
    }
    catch {
        # This is a final catch-all for any other unexpected errors. It's safest to allow the installation
        # to proceed but with a clear warning about the pre-flight check failure.
        Write-Warning "An unexpected error occurred during the pre-flight check: $($_.Exception.Message). Defaulting to allow installation."
        return [PSCustomObject]@{
            ShouldStop = $false
            Reason     = "An unexpected error occurred during pre-flight check: $($_.Exception.Message). Proceeding with workflow as a failsafe."
        }
    }
}

function Test-IsAgentRemoved {
    Write-Verbose "Verifying agent removal by checking for the 'SentinelAgent' service..."
    $isServiceGone = -not (Invoke-ImmyCommand { Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue })
    if ($isServiceGone) {
        Write-Host "[VERIFIED] The 'SentinelAgent' service is no longer present."
        return $true
    }
    Write-Warning "[VERIFICATION FAILED] The 'SentinelAgent' service still exists."
    return $false
}

function Set-C9SentinelOneProtect {
    [CmdletBinding()]
    param() # No parameters for this test version.

    Write-Host "Attempting to set agent protection state to 'Protect'..."

    # We use Invoke-ImmyCommand to run the command on the endpoint and get a structured result back.
    $resultObject = Invoke-ImmyCommand -ScriptBlock {
        try {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
            if (-not $service) { return $null }

            $installDir = Split-Path -Path ($service.PathName.Trim('"')) -Parent
            $sentinelCtlPath = Join-Path -Path $installDir -ChildPath 'SentinelCtl.exe'
            if (-not (Test-Path -LiteralPath $sentinelCtlPath)) { return $null }

            # --- ROBUST CONSOLE CAPTURE PATTERN ---
            # 1. Use the call operator (&) to execute the command.
            # 2. Hardcode the argument to 'protect'.
            # 3. Use '*> &1' to redirect ALL output streams (stdout, stderr, etc.) into a single stream.
            $capturedOutput = & $sentinelCtlPath protect *>&1
            
            # 4. Check the exit code of the last external program that ran.
            $exitCode = $LASTEXITCODE

            # 5. Prepare the final, structured result object.
            $result = @{
                Status = ($exitCode -eq 0)
                Output  = ($capturedOutput | Out-String).Trim()
            }
            
            return [PSCustomObject]$result

        } catch {
            Write-Warning "An unexpected error occurred during endpoint protection state change: $_"
            return $null
        }
    }

    # This code runs back in the Metascript after the endpoint block is finished.
    if ($resultObject) {
        Write-Host "Protection state command completed."
    } else {
        Write-Warning "Could not get a valid result from the endpoint."
    }

    # Return the entire result object for inspection.
    return $resultObject
}

function Set-C9SentinelOneUnprotect {
    [CmdletBinding()]
    param() # The param block is empty for this test.

    # This is your exact, working script block.
    # The passphrase is still hardcoded inside, as requested.
    # No other logic has been changed.

    $Passphrase = "REIN SLAY AWK DELL GIL ELI ALLY FUN FERN MIT FALL BEAM"

    try {
        Write-Verbose "Metascript: Preparing to invoke unprotect command on endpoint..."

        $result = Invoke-ImmyCommand -ScriptBlock {
            # ============================================
            # SYSTEM CONTEXT (This block is our "North Star")
            # ============================================
            try {
                $sentinelService = Get-CimInstance Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction Stop
                $sentinelCtlPath = Join-Path (Split-Path $sentinelService.PathName.Trim('"')) "sentinelctl.exe"
                if (-not (Test-Path $sentinelCtlPath)) {
                    throw "System Context: Could not find sentinelctl.exe at expected path: $sentinelCtlPath"
                }
            } catch {
                return [PSCustomObject]@{ Success = $false; ExitCode = -1; Error = "Failed to find sentinelctl.exe. Details: $_" }
            }
            
            # Using Write-Verbose here to avoid polluting the host output that the main script might check.
            Write-Verbose "System Context: Executing `"$sentinelCtlPath`" unprotect -k ""********"""
            
            $output = & $sentinelCtlPath unprotect -k "$($using:Passphrase)" 2>&1
            $exitCode = $LASTEXITCODE

            return [PSCustomObject]@{
                Success  = ($exitCode -eq 0)
                ExitCode = $exitCode
                Output   = $output | Out-String
            }
        }

        # ============================================
        # BACK IN METASCRIPT CONTEXT
        # ============================================
        Write-Verbose "Metascript: Received result object from endpoint."
        
        if (-not $result.Success) {
            throw "Metascript: Command failed on endpoint with Exit Code $($result.ExitCode). Output: $($result.Output)"
        }

        # The only necessary change to make it a useful function:
        # Instead of writing "VICTORY" to the host, we return the successful result object.
        return $result
    }
    catch {
        Write-Error "A fatal error occurred in the Set-C9SentinelOneUnprotect function: $_"
        throw
    }
}

function Invoke-C9EndpointCommand {
<#
.SYNOPSIS
    Executes a command-line process on an endpoint, capturing all output streams and the exit code.
.DESCRIPTION
    A robust Metascript wrapper for Invoke-ImmyCommand that executes a specified executable on the target machine in the SYSTEM context.
    It uses the .NET System.Diagnostics.Process class to reliably capture standard output (stdout), standard error (stderr), and the process exit code.
    This function is designed to be a generic, reusable replacement for simple Invoke-ImmyCommand calls for executables.
.PARAMETER FilePath
    The full path to the executable file on the target endpoint.
.PARAMETER ArgumentList
    An array of strings representing the arguments to pass to the executable. Arguments containing spaces will be automatically and correctly quoted.
.PARAMETER WorkingDirectory
    The working directory from which to run the executable.
.PARAMETER TimeoutSeconds
    The maximum number of seconds to wait for the command to complete. Defaults to 600 (10 minutes).
.OUTPUTS
    A PSCustomObject containing the following properties:
    - ExitCode ([int]): The exit code returned by the process.
    - StandardOutput ([string]): The complete standard output from the process.
    - StandardError ([string]): The complete standard error from the process.
.EXAMPLE
    # Execute sentinelctl.exe status and capture the output
    $statusResult = Invoke-C9EndpointCommand -FilePath "C:\Program Files\SentinelOne\Sentinel Agent\sentinelctl.exe" -ArgumentList "status"
    if ($statusResult.ExitCode -eq 0) {
        Write-Host "S1 Status: $($statusResult.StandardOutput)"
    }
.EXAMPLE
    # Execute sentinelctl.exe unprotect with a passphrase containing spaces
    $passphrase = "my secret pass phrase"
    $unprotectResult = Invoke-C9EndpointCommand -FilePath "C:\Program Files\SentinelOne\Sentinel Agent\sentinelctl.exe" -ArgumentList "unprotect", "-k", $passphrase
    if ($unprotectResult.StandardError) {
        Write-Error "Error during unprotect: $($unprotectResult.StandardError)"
    }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 600
    )

    Write-Verbose "Preparing to execute '$FilePath' via Invoke-C9EndpointCommand."
    if ($ArgumentList) {
        Write-Verbose "Arguments: $($ArgumentList -join ' ')"
    }

    # The core logic is performed within Invoke-ImmyCommand to run in the SYSTEM context on the endpoint.
    $result = Invoke-ImmyCommand -Timeout $TimeoutSeconds -ScriptBlock {
        param(
            [string]$Path,
            [string[]]$Arguments,
            [string]$WorkDir
        )

        # Defensive check to ensure the executable exists on the endpoint before proceeding.
        if (-not (Test-Path -Path $Path -PathType Leaf)) {
            throw "Executable not found at path: $Path"
        }

        # --- Argument Handling: Solves the Passphrase/Spaces Blocker ---
        # This block correctly formats the arguments into a single string that the .NET Process class can parse.
        # It iterates through each argument and wraps any that contain whitespace in double quotes.
        $formattedArgs = foreach ($arg in $Arguments) {
            if ($arg -match '\s') {
                "`"$arg`"" # Wrap arguments with spaces in quotes
            } else {
                $arg
            }
        }
        $argumentString = $formattedArgs -join ' '

        Write-Host "Executing: `"$Path`" $argumentString"

        # --- .NET Process Execution: The pattern from the Sysmon script ---
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $Path
        $pinfo.Arguments = $argumentString
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true # Correctly captures the error stream
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        if (-not [string]::IsNullOrWhiteSpace($WorkDir)) {
            $pinfo.WorkingDirectory = $WorkDir
        }

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo

        try {
            # Start the process and wait for it to finish.
            $p.Start() | Out-Null
            $p.WaitForExit()

            # Read the output streams *after* the process has exited.
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()

            # Return a structured object with all results.
            return [PSCustomObject]@{
                ExitCode       = $p.ExitCode
                StandardOutput = $stdout
                StandardError  = $stderr
            }
        }
        catch {
            # Catch any exceptions during process start (e.g., permissions issues)
            throw "Failed to start or monitor process '$Path'. Error: $_"
        }
        finally {
            # Ensure the process object is disposed of to release resources.
            if ($p) {
                $p.Dispose()
            }
        }

    } -ArgumentList @($FilePath, $ArgumentList, $WorkingDirectory)

    # Log the captured output to the ImmyBot session log for excellent visibility.
    if ($result) {
        Write-Host "Command finished with Exit Code: $($result.ExitCode)."
        if (-not [string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            Write-Host "--- Standard Output ---"
            Write-Host $result.StandardOutput
            Write-Host "-----------------------"
        }
        if (-not [string]::IsNullOrWhiteSpace($result.StandardError)) {
            Write-Warning "--- Standard Error ---"
            Write-Warning $result.StandardError
            Write-Warning "----------------------"
        }
    }

    return $result
}

Export-ModuleMember -Function @(
    'Get-C9SentinelOneInfo',
    'Get-C9S1LocalAgentId',
    'Test-C9S1LocalUpgradeAuthorization',
    'Test-IsAgentRemoved',
    'Set-C9SentinelOneProtect',
    'Set-C9SentinelOneUnprotect',
    'Invoke-C9EndpointCommand'
)