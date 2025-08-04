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

    Write-Host "Querying endpoint for SentinelOne agent information..."

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

    Write-Host "Attempting to retrieve SentinelOne Agent ID from the local endpoint."
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
            Write-Host "No local Agent ID was found."
            return $null
        }

        Write-Host "Successfully retrieved local Agent ID: $result"
        return $result
    }
    catch {
        Write-Warning "An error occurred while trying to retrieve the local Agent ID: $($_.Exception.Message)"
        return $null
    }
}

function Test-EndpointSafeToReboot {
    <#
    .SYNOPSIS
        (Orchestrator) Determines if an endpoint is safe for invasive work, prioritizing explicit platform policies.
    .DESCRIPTION
        This is the definitive gatekeeper function. It performs a three-tiered safety check:
        1.  (Highest Priority) Checks an explicitly passed-in platform policy from a calling script.
        2.  (Second Priority) Checks for the global '$RebootPreference' variable from a Maintenance Task.
        3.  (Final Check) If no platform policy is found, it calls specialist functions like Get-C9UserIdleTime
            and Get-ComputerLockedStatus to perform granular checks.
    .PARAMETER PlatformPolicy
        An explicit policy string (e.g., "Suppress") passed from a calling script (e.g., an Install script).
    .PARAMETER InitialDelaySeconds
        An optional delay (in seconds) to apply before running checks, allowing system state to settle.
    .PARAMETER Computer
        The ImmyBot computer object to test. Defaults to the computer in the current context via (Get-ImmyComputer).
    .PARAMETER RequiredIdleMinutes
        The minimum number of minutes a user must be idle for the endpoint to be considered safe. Defaults to 30.
    .PARAMETER AllowWhenLocked
        A switch to indicate if a locked computer should be considered safe, regardless of idle time. Defaults to $true.
    .PARAMETER MaintenanceWindowStart
        The start time for a custom maintenance window in 24-hour format (e.g., "22:00"). This check runs IN ADDITION to the platform policy check.
    .PARAMETER MaintenanceWindowEnd
        The end time for a custom maintenance window in 24-hour format (e.g., "05:00").
    .PARAMETER IgnorePlatformPolicy
        A switch to bypass the primary check of the ImmyBot platform's '$RebootPreference' variable. Use with caution.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$PlatformPolicy,

        [Parameter(Mandatory = $false)]
        [int]$InitialDelaySeconds = 5,

        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer),

        [Parameter(Mandatory = $false)]
        [int]$RequiredIdleMinutes = 30,

        [Parameter(Mandatory = $false)]
        [bool]$AllowWhenLocked = $true,

        [Parameter(Mandatory = $false)]
        [string]$MaintenanceWindowStart,

        [Parameter(Mandatory = $false)]
        [string]$MaintenanceWindowEnd,

        [Parameter(Mandatory = $false)]
        [switch]$IgnorePlatformPolicy

  #      [Parameter(Mandatory = $false)]
  #      [switch]$ShowVerbose
    )

 #   if ($ShowVerbose -or $PSBoundParameters.ContainsKey('Verbose')) {
 #       $VerbosePreference = 'Continue'
 #       Write-Host "[VERBOSE MODE ENABLED] Starting endpoint safety assessment..." -ForegroundColor Yellow
 #   }

$FunctionName = "Test-C9EndpointSafeToReboot"

    $result = [ordered]@{
        IsSafe          = $false
        Reason          = "Initial state."
        PlatformPolicy  = "Unknown"
        IdleTimeMinutes = -1
        LockStatus      = "Unknown"
        LoggedOnUser    = "Unknown"
        IsInMaintWindow = $false
    }

    try {
        if ($InitialDelaySeconds -gt 0) {
            Write-Host "[$ScriptName - $FunctionName] Applying initial settle-time delay of $InitialDelaySeconds second(s)..."
            Start-Sleep -Seconds $InitialDelaySeconds
        }
        
        $policySource = "None"
        $effectivePolicy = ""
        if (-not [string]::IsNullOrWhiteSpace($PlatformPolicy)) {
            $policySource = "Parameter"
            $effectivePolicy = $PlatformPolicy
        } elseif (Test-Path 'variable:global:RebootPreference') {
            $policySource = "Global Variable"
            $effectivePolicy = $global:RebootPreference
        }

        if ($policySource -ne "None") {
            $result.PlatformPolicy = $effectivePolicy
            Write-Host "[$ScriptName - $FunctionName] Detected platform policy via ${policySource}: RebootPreference = '$effectivePolicy'"
            
            if ($effectivePolicy -eq "Suppress" -and -not $IgnorePlatformPolicy.IsPresent) {
                $result.IsSafe = $false
                $result.Reason = "Action suppressed by platform policy (RebootPreference='Suppress')."
                return New-Object -TypeName PSObject -Property $result
            }
        } else {
            $result.PlatformPolicy = "Not Set"
            Write-Host "[$ScriptName - $FunctionName] No platform policy found. Proceeding with granular checks."
        }


        Write-Host "[$ScriptName - $FunctionName] Gathering granular endpoint status for $($Computer.Name)..."

        $idleTime = Get-C9UserIdleTime -Computer $Computer -ErrorAction Stop
        $lockStatus = Get-ComputerLockedStatus -Computer $Computer -ErrorAction Stop
        $result.IdleTimeMinutes = [int]$idleTime.TotalMinutes
        $result.LockStatus = $lockStatus
        
        Write-Host "[$ScriptName - $FunctionName] Endpoint idle for $($result.IdleTimeMinutes) minute(s). Lock status: $($result.LockStatus)."

        try {
            $loggedOnUsers = @(Get-LoggedOnUser -Computer $Computer -ErrorAction SilentlyContinue)
            if ($null -ne $loggedOnUsers) {
                $result.LoggedOnUser = $loggedOnUsers -join ', '
                Write-Host "[$ScriptName - $FunctionName] Found logged on user(s): $($result.LoggedOnUser)."

            } else {
                $result.LoggedOnUser = "None"
                Write-Host "[$ScriptName - $FunctionName] No interactive users found."
            }
        }
        catch {
            Write-Warning "[$ScriptName - $FunctionName] Could not determine logged on user. $_"
            $result.LoggedOnUser = "Error"
        }
        
        $isWithinMaintenanceWindow = $false
        if (-not [string]::IsNullOrWhiteSpace($MaintenanceWindowStart) -and -not [string]::IsNullOrWhiteSpace($MaintenanceWindowEnd)) {
            Write-Host "[$ScriptName - $FunctionName] Checking custom maintenance window: $MaintenanceWindowStart - $MaintenanceWindowEnd"
            
            try {
                $endpointNow = Invoke-ImmyCommand -Computer $Computer -ScriptBlock { 
                    Write-Host "[$($using:ScriptName) - $($using:FunctionName)] Getting current time on endpoint..."
                    Get-Date 
                } -ErrorAction Stop
                
                $start = Get-Date -Date $endpointNow.Date -Hour ($MaintenanceWindowStart.Split(':')[0]) -Minute ($MaintenanceWindowStart.Split(':')[1])
                $end = Get-Date -Date $endpointNow.Date -Hour ($MaintenanceWindowEnd.Split(':')[0]) -Minute ($MaintenanceWindowEnd.Split(':')[1])

                if ($start -gt $end) { 
                    if (($endpointNow -ge $start) -or ($endpointNow -lt $end)) { 
                        $isWithinMaintenanceWindow = $true 
                    } 
                } else { 
                    if (($endpointNow -ge $start) -and ($endpointNow -lt $end)) { 
                        $isWithinMaintenanceWindow = $true 
                    } 
                }
                
                $result.IsInMaintWindow = $isWithinMaintenanceWindow
                Write-Host "[$ScriptName - $FunctionName] Endpoint current time: $($endpointNow.ToString('yyyy-MM-dd HH:mm:ss')). Is within custom maintenance window: $isWithinMaintenanceWindow."
            }
            catch { 
                Write-Warning "[$ScriptName - $FunctionName] Failed to check custom maintenance window: $_" 
            }
        }

        if ($result.LockStatus -eq 'LoggedOut' -or $idleTime -eq [TimeSpan]::MaxValue) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint is safe because no user is logged on."
        }
        elseif ($isWithinMaintenanceWindow) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint is safe because it is within the custom-defined maintenance window ($MaintenanceWindowStart - $MaintenanceWindowEnd)."
        }
        elseif ($result.LockStatus -eq 'Locked' -and $AllowWhenLocked) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint is safe because the screen is locked."
        }
        elseif ($result.IdleTimeMinutes -ge $RequiredIdleMinutes) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint has been idle for $($result.IdleTimeMinutes) minutes, which meets the $($RequiredIdleMinutes)-minute requirement."
        }
        else {
            $result.IsSafe = $false
            $result.Reason = "User is active (Idle for $($result.IdleTimeMinutes) of $($RequiredIdleMinutes) mins) and endpoint is not locked or within a custom maintenance window."
        }

    } catch {
        $result.IsSafe = $false
        $result.Reason = "An error occurred while checking endpoint status: $($_.Exception.Message)"
        Write-Error $result.Reason
    }

    Write-Host "[$ScriptName - $FunctionName] Endpoint safety check completed. IsSafe: $($result.IsSafe), Reason: $($result.Reason)."
    
    return New-Object -TypeName PSObject -Property $result
}

function Test-C9S1LocalUpgradeAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AgentId
    )

    $endpoint = "agents/$AgentId/local-upgrade-authorization"
    Write-Host "Checking API endpoint '$endpoint' for agent protection status."

    try {
        # We expect a successful call to return data with an 'enabled' property.
        $response = Invoke-C9S1RestMethod -Endpoint $endpoint
        
        # The API returns { "data": { "enabled": true/false } } on success
        if ($null -ne $response.enabled -and $response.enabled) {
            Write-Host "API Response: Local upgrade authorization is ENABLED."
            return $true
        }
        else {
            Write-Host "API Response: Local upgrade authorization is DISABLED."
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

    Write-Host "Starting SentinelOne installation pre-flight check..."

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

function Resolve-InstallerAvailable {
<#
.SYNOPSIS
    Ensures a file is available on the endpoint, downloading it if necessary, with authentication support.
.PARAMETER DownloadUrl
    The public URL from which to download the file.
.PARAMETER FileName
    The name of the file (e.g., "MyTool.exe") to be saved on the endpoint.
.PARAMETER AuthHeader
    A hashtable containing the authentication headers required for the download (e.g., @{ 'Authorization' = "Bearer ..." }).
.OUTPUTS
    String. The full path to the staged file on the endpoint.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DownloadUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [hashtable]$AuthHeader
    )

    # Define a persistent, predictable staging directory on the endpoint
    $stagingDir = 'C:\ProgramData\C9Automation\Installers\SentinelOne'
    $destinationPath = Join-Path -Path $stagingDir -ChildPath $FileName
    
    # Check if the file already exists on the endpoint. This must run in the System context.
    $fileExists = Invoke-ImmyCommand -ScriptBlock {
        param($path)
        # Ensure the staging directory exists
        if (-not (Test-Path -LiteralPath (Split-Path $path))) {
            New-Item -Path (Split-Path $path) -ItemType Directory -Force | Out-Null
        }
        return Test-Path -LiteralPath $path
    } -ArgumentList $destinationPath
    
    if ($fileExists) {
        Write-Host "[RESOLVE] File '$FileName' already exists in staging directory. Skipping download."
        return $destinationPath
    }

    # If it doesn't exist, download it. This runs in the Metascript context.
    Write-Host "[RESOLVE] Downloading '$FileName' to endpoint path '$destinationPath'..."
    # The '-Headers' parameter is the critical addition for authenticated downloads.
    Download-File -Url $DownloadUrl -OutFile $destinationPath -Headers $AuthHeader
    Write-Host "[RESOLVE] SUCCESS: File downloaded."
    return $destinationPath
}

function Set-C9SentinelOneUnprotect {
<#
.SYNOPSIS
    Disables the SentinelOne agent's self-protection using a passphrase.
.DESCRIPTION
    A robust Metascript function that orchestrates the unprotection of a SentinelOne agent.
    It uses Get-C9SentinelOneInfo to locate the agent and Invoke-C9EndpointCommand to execute
    the 'sentinelctl unprotect' command, passing the passphrase securely. It includes
    intelligent error handling to distinguish between benign warnings and true failures.
.PARAMETER Passphrase
    The agent-specific passphrase required to disable protection. This string can contain spaces.
.OUTPUTS
    Boolean. Returns $true on success, throws a terminating error on failure.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Passphrase
    )

    # Step 1: Find the agent using our helper function
    Write-Host "Attempting to locate the SentinelOne agent..."
    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info) {
        throw "Cannot unprotect agent: SentinelOne agent was not found on the endpoint."
    }

    # Step 2: Prepare and execute the command using our robust command wrapper
    Write-Host "Disabling SentinelOne agent protection via sentinelctl..."
    $argumentList = "unprotect", "-k", $Passphrase
    $result = Invoke-C9EndpointCommand -FilePath $s1Info.SentinelCtlPath -ArgumentList $argumentList

    # Step 3: Intelligent Error Handling
    if ($result.ExitCode -ne 0) {
        throw "Failed to unprotect SentinelOne agent. The sentinelctl.exe process returned exit code: $($result.ExitCode). Error Output: $($result.StandardError)"
    }
    
    # Ignore known, benign warnings from sentinelctl.exe
    if ($result.StandardError -and $result.StandardError -notmatch 'In-Process Client') {
        throw "An unexpected error was reported by sentinelctl.exe during unprotect: $($result.StandardError)"
    }
    
    # Step 4: Final validation
    if ($result.StandardOutput -match 'Protection is off|Protection disabled') {
        Write-Host "[SUCCESS] SentinelOne agent protection has been successfully disabled."
        return $true
    } else {
        throw "Unprotect command completed, but success could not be verified from the output. Output: $($result.StandardOutput)"
    }
}

function Set-C9SentinelOneProtect {
    [CmdletBinding()]
    param()
    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info) { throw "Cannot protect agent: SentinelOne agent was not found." }
    Invoke-C9EndpointCommand -FilePath $s1Info.SentinelCtlPath -ArgumentList "protect"
}

function Invoke-C9EndpointCommand {
<#
.SYNOPSIS
    Executes a command-line process on an endpoint, capturing all output streams and the exit code.

.DESCRIPTION
    A robust Metascript wrapper for Invoke-ImmyCommand that executes a specified executable on the target machine in the SYSTEM context.
    
    This function is designed to be a generic, reusable replacement for simple Invoke-ImmyCommand calls for executables. It provides three key advantages:
    1.  Reliably captures standard output (stdout), standard error (stderr), and the process exit code into a single, structured object.
    2.  Solves complex argument-passing issues by correctly handling arguments that contain spaces or quotes (e.g., passphrases, file paths).
    3.  Standardizes command execution and logging across all scripts.

.PARAMETER FilePath
    The full path to the executable file on the target endpoint.

.PARAMETER ArgumentList
    An array of strings representing the arguments to pass to the executable. 
    Each part of the command (the verb, switch, and value) should be a separate element in the array.
    The function will automatically handle quoting for arguments that contain spaces.
    
    For example, to run 'unprotect -k "my secret phrase"', the array should be:
    @('unprotect', '-k', 'my secret phrase')

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
    # Example 1: Run a simple command with no arguments.
    $statusResult = Invoke-C9EndpointCommand -FilePath "C:\Program Files\S1\sentinelctl.exe" -ArgumentList "status"
    
    if ($statusResult.ExitCode -eq 0) {
        Write-Host "S1 Status: $($statusResult.StandardOutput)"
    }

.EXAMPLE
    # Example 2: Run a command with a complex argument (e.g., a passphrase with spaces).
    $s1Path = "C:\Program Files\S1\sentinelctl.exe"
    $passphrase = "my secret pass phrase"
    $arguments = "unprotect", "-k", $passphrase

    $unprotectResult = Invoke-C9EndpointCommand -FilePath $s1Path -ArgumentList $arguments

    if ($unprotectResult.StandardError -and $unprotectResult.StandardError -notmatch "In-Process Client") {
        # Check for any real errors, ignoring known benign warnings.
        throw "An unexpected error occurred during unprotect: $($unprotectResult.StandardError)"
    } else {
        Write-Host "Unprotect command completed successfully."
    }

.NOTES
    Author: Josh Phillips
    Date:   July 24, 2025

    Architectural Choice: Why `$using:` is used instead of `-ArgumentList`
    ---------------------------------------------------------------------
    Initial versions of this function attempted to pass parameters into the Invoke-ImmyCommand script block using the -ArgumentList parameter and a corresponding param() block.
    
    Extensive diagnostic testing proved this method to be unreliable within the ImmyBot platform for complex arguments. It resulted in a persistent parameter binding bug where arguments were scrambled upon arrival at the endpoint (e.g., the command 'status' was being bound to the FilePath parameter).
    
    The current implementation intentionally bypasses the -ArgumentList parameter. Instead, it uses the PowerShell `$using:` scope modifier (e.g., `$using:FilePath`) to directly and reliably inject variables from the parent Metascript into the endpoint's System context. This is the most direct, explicit, and robust method for passing data across the ImmyBot context boundary and aligns with the project's established architectural best practices.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath,

        [Parameter(Mandatory = $false, Position = 1)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 600
    )

    Write-Host "Preparing to execute '$FilePath' with arguments: $($ArgumentList -join ' ')"

    # We use the $using: scope modifier to reliably pass variables into the script block,
    # bypassing the unreliable -ArgumentList parameter binding mechanism.
    $result = Invoke-ImmyCommand -Timeout $TimeoutSeconds -ScriptBlock {
        
        # We do not use a param() block here; we access the variables directly via $using:
        Write-Host "Endpoint received command: '$($using:FilePath)'"
        Write-Host "Endpoint received argument: '$($using:ArgumentList -join ' ')'"
        
        if (-not (Test-Path -Path $using:FilePath -PathType Leaf)) {
            throw "Executable not found at path: $($using:FilePath)"
        }

        # This logic correctly handles arguments with spaces by quoting them.
        $formattedArgs = foreach ($arg in $using:ArgumentList) {
            if ($arg -match '\s') { "`"$arg`"" } else { $arg }
        }
        $argumentString = $formattedArgs -join ' '

        Write-Host "Executing: `"$($using:FilePath)`" $argumentString"

        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $using:FilePath
        $pinfo.Arguments = $argumentString
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        if (-not [string]::IsNullOrWhiteSpace($using:WorkingDirectory)) {
            $pinfo.WorkingDirectory = $using:WorkingDirectory
        }
        
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo

        try {
            $p.Start() | Out-Null
            $p.WaitForExit()
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()
            return [PSCustomObject]@{ ExitCode = $p.ExitCode; StandardOutput = $stdout; StandardError = $stderr }
        }
        catch { throw "Failed to start or monitor process '$($using:FilePath)'. Error: $_" }
        finally { if ($p) { $p.Dispose() } }

    } # Note: No -ArgumentList is used here.

    # Log the full results to the Metascript log for excellent visibility.
    if ($result) {
        Write-Host "Command finished with Exit Code: $($result.ExitCode)."
        if (-not [string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            Write-Host "--- Start Standard Output ---"
            Write-Host $result.StandardOutput
            Write-Host "--- End Standard Output ---"
        }
        if (-not [string]::IsNullOrWhiteSpace($result.StandardError)) {
            Write-Warning "--- Start Standard Error ---"
            Write-Warning $result.StandardError
            Write-Warning "--- End Standard Error ---"
        }
    }

    return $result
}

Export-ModuleMember -Function @(
    'Get-C9SentinelOneInfo',
    'Get-C9S1LocalAgentId',
    'Test-C9S1LocalUpgradeAuthorization',
    'Test-EndpointSafeToReboot',
    'Resolve-InstallerAvailable',
    'Set-C9SentinelOneProtect',
    'Set-C9SentinelOneUnprotect',
    'Invoke-C9EndpointCommand'
)