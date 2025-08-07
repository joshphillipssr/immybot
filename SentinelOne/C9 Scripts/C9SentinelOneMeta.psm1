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

    $FunctionName = "Get-C9SentinelOneInfo"

    Write-Host "[$ScriptName - $FunctionName] Querying endpoint for SentinelOne agent information..."

    # This single Invoke-ImmyCommand call gathers all info from the endpoint in one go.
    $infoObject = Invoke-ImmyCommand -ScriptBlock {

        # This logic is based on the proven detection script pattern.
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

        # If the service doesn't exist, the agent is not installed. Return $null.
        if (-not ($service -and $service.PathName)) {
            Write-Warning "[$ScriptName - $FunctionName] SentinelAgent service not found on endpoint. Agent is not installed."
            return $null
        }

        # If the service exists, proceed to gather more details.
        $agentExePath = $service.PathName.Trim('"')
        $installPath = Split-Path -Path $agentExePath
        $sentinelCtlPath = Join-Path -Path $installPath -ChildPath "sentinelctl.exe"

        # Final validation: Ensure the paths reported by the service actually exist.
        if (-not (Test-Path -LiteralPath $agentExePath)) {
            Write-Error "[$ScriptName - $FunctionName] Service found, but its executable path is invalid: $agentExePath"
            return $null
        }

        if (-not (Test-Path -LiteralPath $sentinelCtlPath)) {
            Write-Error "[$ScriptName - $FunctionName] Agent found, but sentinelctl.exe is missing from its directory: $sentinelCtlPath"
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
        Write-Host "[$ScriptName - $FunctionName] Successfully retrieved SentinelOne agent info. Version: $($infoObject.Version)"
    } else {
        Write-Warning "[$ScriptName - $FunctionName] Get-C9SentinelOneInfo did not find a valid agent installation on the endpoint."
    }
    
    return $infoObject
}

function Get-C9S1LocalAgentId {
    [CmdletBinding()]
    param()

    $FunctionName = "Get-C9S1LocalAgentId"

    Write-Host "[$ScriptName - $FunctionName] Attempting to retrieve SentinelOne Agent ID from the local endpoint."
    try {
        # This scriptblock runs on the endpoint as SYSTEM.
        # It's self-contained and has one job: get the agent ID.
        $result = Invoke-ImmyCommand -ScriptBlock {
            # Use Resolve-Path for robustly finding the executable
            $sentinelCtlPath = Resolve-Path "C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe" -ErrorAction SilentlyContinue
            if (-not $sentinelCtlPath) {
                Write-Warning "[$using:ScriptName - $using:FunctionName] SentinelCtl.exe not found on the endpoint."
                # Return null explicitly if the exe isn't found
                return $null
            }
            
            # Execute the command to get the agent ID.
            # We trim to ensure no leading/trailing whitespace.
            $agentId = (& $sentinelCtlPath.Path agent_id).Trim()
            return $agentId
        }

        if ([string]::IsNullOrWhiteSpace($result)) {
            Write-Host "[$using:ScriptName - $using:FunctionName] No local Agent ID was found."
            return $null
        }

        Write-Host "[$using:ScriptName - $using:FunctionName] Successfully retrieved local Agent ID: $result"
        return $result
    }
    catch {
        Write-Warning "[$ScriptName - $FunctionName] An error occurred while trying to retrieve the local Agent ID: $($_.Exception.Message)"
        return $null
    }
}

function Get-C9SentinelOneVersion {
    <#
    .SYNOPSIS
        A Metascript function that retrieves the installed version of the SentinelOne agent from an endpoint.
    .DESCRIPTION
        This function is designed to be called from a Metascript context. It uses Invoke-ImmyCommand
        to execute detection logic on the endpoint. It reliably finds the agent's version by querying
        the running service for its executable path and then reading the file's version metadata.
    .RETURNS
        [string] The product version of the SentinelOne agent if found (e.g., "24.2.3.471").
        $null if the agent is not found or if the version cannot be determined.
    .EXAMPLE
        $installedVersion = Get-C9SentinelOneVersion
        if ($installedVersion) {
            Write-Host "Detected SentinelOne Version: $installedVersion"
        } else {
            Write-Warning "Could not detect an installed SentinelOne agent."
        }
    #>

    [CmdletBinding()]
    param()

    $FunctionName = "Get-C9SentinelOneVersion"

    Write-Host "[$ScriptName - $FunctionName] Attempting to get S1 version from endpoint..."
    
    # Use the standard "bridge" to run detection logic on the endpoint.
    $version = Invoke-ImmyCommand -ScriptBlock {
        # This entire script block runs on the endpoint as SYSTEM.
        try {
            # Find the service to get the authoritative path to the executable.
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

            if ($service -and $service.PathName) {
                $exePath = $service.PathName.Trim('"')
                
                # Verify the path reported by the service actually exists.
                if (Test-Path -LiteralPath $exePath) {
                    # Get the file's version info. This is the most reliable source.
                    $fileInfo = Get-Item -LiteralPath $exePath -ErrorAction SilentlyContinue
                    $productVersion = $fileInfo.VersionInfo.ProductVersion
                    
                    if ($productVersion) {
                        # SUCCESS: We have the version. Return it to the Metascript.
                        return $productVersion
                    }
                }
            }
            
            # If any of the above steps fail, we fall through to here.
            # Return $null to indicate the agent was not found or version is unknown.
            return $null

        } catch {
            # In case of an unexpected terminating error, log it and return null.
            Write-Warning "An unexpected error occurred during endpoint detection: $_"
            return $null
        }
    }

    if ($version) {
        Write-Host "[$ScriptName - $FunctionName] Successfully retrieved version: $version"
    } else {
        Write-Host "[$ScriptName - $FunctionName] SentinelOne agent not found or version could not be determined."
    }

    return $version
}

function Get-C9S1EndpointData {
    #Requires -Version 5.1
    #Requires -Modules C9S1EndpointTools
    <#
    .SYNOPSIS
        Get-S1Health.ps1 - The 'Get' script for the SentinelOne Health task.
    .DESCRIPTION
        This script collects comprehensive health data about the local SentinelOne agent.
        It is intended for use in an ImmyBot 'Monitor' task to inventory agent status.

        It performs its work by importing the C9S1EndpointTools.psm1 module and calling the
        Get-C9S1LocalHealthReport function, which returns a detailed PSCustomObject.
    .OUTPUTS
        [PSCustomObject] A detailed object containing the S1 agent's local health status.
    .NOTES
        Author:     Josh Phillips (Consulting) & C9.AI
        Created:    07/15/2025
        Version:    2.0.0
    #>

    param()

    $FunctionName = "Get-C9S1EndpointData"

    try {
        # The #Requires statement above handles the import of our custom module.
        # We can use Write-Host for high-level status messages that are always visible in ImmyBot logs.
        Write-Host "[$ScriptName - $FunctionName] Executing SentinelOne Health 'Get' script."
        Write-Host "[$ScriptName - $FunctionName] This script gathers raw data for inventory or for a 'Test' script to evaluate."

        # Call the master function from our module. It handles all its own detailed logging.
        # The output of this function is the final return value of this script.
        $healthReport = Get-C9S1LocalHealthReport

        Write-Host "[$ScriptName - $FunctionName] Successfully generated health report. Returning data object."
        
        # Returning the object is the last action. ImmyBot will capture this.
        return $healthReport
    }
    catch {
        # If anything goes wrong (e.g., module not found, catastrophic function error),
        # write a clear error and re-throw to ensure ImmyBot registers the failure.
        $errorMessage = "A fatal error occurred in Get-S1Health.ps1: $($_.Exception.Message)"
        Write-Error $errorMessage
        throw $errorMessage
    }
}

function Get-C9SentinelOneStatus {
    <#
    .SYNOPSIS
        (Refactored) A Metascript function that retrieves and parses the output of 'sentinelctl.exe status'.
    .DESCRIPTION
        This function locates sentinelctl.exe via Get-C9SentinelOneInfo and executes the 'status' command
        using the robust Invoke-C9EndpointCommand wrapper. It parses the key-value output into a
        structured object for easy analysis.
    .OUTPUTS
        A PSCustomObject containing parsed status data, or $null on failure.
    #>
    [CmdletBinding()]
    param()

    $FunctionName = "Get-C9SentinelOneStatus"
    Write-Host "[$ScriptName - $FunctionName] Getting agent status via sentinelctl.exe..."

    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info -or -not $s1Info.SentinelCtlPath) {
        Write-Warning "[$ScriptName - $FunctionName] Cannot run 'status' command; SentinelCtl.exe path is unknown."
        return $null
    }

    # =========================================================================
    # --- BEGIN CORRECTED SECTION (Fix #1: $using scope) ---
    # =========================================================================
    # Assign the complex property to a simple variable first.
    $sentinelCtlPath = $s1Info.SentinelCtlPath

    # Now, use the simple variable with the $using: modifier. This is safe.
    if (-not (Invoke-ImmyCommand -ScriptBlock { Test-Path $using:sentinelCtlPath })) {
        Write-Warning "[$ScriptName - $FunctionName] SentinelCtl.exe not found at path: $($sentinelCtlPath)"
        return $null
    }
    # =========================================================================
    # --- END CORRECTED SECTION ---
    # =========================================================================

    # Use the simple variable for the command execution as well.
    $ctlResult = Invoke-C9EndpointCommand -FilePath $sentinelCtlPath -ArgumentList "status"
    
    if ($ctlResult.ExitCode -ne 0) {
        Write-Warning "[$ScriptName - $FunctionName] 'sentinelctl.exe status' failed with Exit Code: $($ctlResult.ExitCode)."
        # We still return the object, the exit code is valuable data.
    }
    
    $outputLines = $ctlResult.StandardOutput -split '(?:\r\n|\r|\n)'
    $statusData = [ordered]@{
        # Add the raw execution results for deep diagnostics
        ExitCode       = $ctlResult.ExitCode
        RawOutput      = $ctlResult.StandardOutput
        RawError       = $ctlResult.StandardError
        # Add a property to explicitly state if the command ran successfully
        IsHealthy      = ($ctlResult.ExitCode -eq 0)
    }

    # =========================================================================
    # --- BEGIN CORRECTED SECTION (Fix #2: Parsing Logic) ---
    # =========================================================================
    foreach ($line in $outputLines) {
        # We only care about lines that are key:value pairs.
        if ($line -like '*:*') {
            $key, $value = $line.Split(':', 2).Trim()
            # Make property name PowerShell-friendly by replacing spaces with underscores.
            $propName = $key.Replace(' ', '_') 
            $statusData[$propName] = $value
        }
        # We no longer have an 'elseif' block. Lines without a colon are ignored.
    }
    # =========================================================================
    # --- END CORRECTED SECTION ---
    # =========================================================================

    Write-Host "[$ScriptName - $FunctionName] Successfully parsed sentinelctl status."
    return New-Object -TypeName PSObject -Property $statusData
}

function Test-C9S1LocalUpgradeAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AgentId
    )

    $FunctionName = "Test-C9S1LocalUpgradeAuthorization"

    $endpoint = "agents/$AgentId/local-upgrade-authorization"
    Write-Host "[$ScriptName - $FunctionName] Checking API endpoint '$endpoint' for agent protection status."

    try {
        # We expect a successful call to return data with an 'enabled' property.
        $response = Invoke-C9S1RestMethod -Endpoint $endpoint
        
        # The API returns { "data": { "enabled": true/false } } on success
        if ($null -ne $response.enabled -and $response.enabled) {
            Write-Host "[$ScriptName - $FunctionName] API Response: Local upgrade authorization is ENABLED."
            return $true
        }
        else {
            Write-Host "[$ScriptName - $FunctionName] API Response: Local upgrade authorization is DISABLED."
            return $false
        }
    }
    catch {
        # Check if the error is specifically a 404 Not Found, which indicates a ghost agent.
        if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            Write-Warning "[$ScriptName - $FunctionName] Agent ID '$AgentId' returned a 404 (Not Found) from the API. This is a ghost agent."
            # We throw a specific string that the calling function can catch and interpret.
            throw "GHOST_AGENT"
        }
        
        # For any other API error, we log it and assume it's not protected as a failsafe.
        Write-Warning "[$ScriptName - $FunctionName] An unexpected API error occurred while checking local upgrade authorization: $($_.Exception.Message)"
        return $false
    }
}

function Test-S1InstallPreFlight {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $FunctionName = "Test-S1InstallPreFlight"

    Write-Host "[$ScriptName - $FunctionName] Starting SentinelOne installation pre-flight check..."

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
        Write-Warning "[$ScriptName - $FunctionName] An unexpected error occurred during the pre-flight check: $($_.Exception.Message). Defaulting to allow installation."
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

    $FunctionName = "Resolve-InstallerAvailable"

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
        Write-Host "[$ScriptName - $FunctionName] File '$FileName' already exists in staging directory. Skipping download."
        return $destinationPath
    }

    # If it doesn't exist, download it. This runs in the Metascript context.
    Write-Host "[$ScriptName - $FunctionName] [RESOLVE] Downloading '$FileName' to endpoint path '$destinationPath'..."
    # The '-Headers' parameter is the critical addition for authenticated downloads.
    Download-File -Url $DownloadUrl -OutFile $destinationPath -Headers $AuthHeader
    Write-Host "[$ScriptName - $FunctionName] [RESOLVE] SUCCESS: File downloaded."
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

    $FunctionName = "Set-C9SentinelOneUnprotect"

    # Step 1: Find the agent using our helper function
    Write-Host "[$ScriptName - $FunctionName] Attempting to locate the SentinelOne agent..."
    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info) {
        throw "Cannot unprotect agent: SentinelOne agent was not found on the endpoint."
    }

    # Step 2: Prepare and execute the command using our robust command wrapper
    Write-Host "[$ScriptName - $FunctionName] Disabling SentinelOne agent protection via sentinelctl..."
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
        Write-Host "[$ScriptName - $FunctionName] [SUCCESS] SentinelOne agent protection has been successfully disabled."
        return $true
    } else {
        throw "Unprotect command completed, but success could not be verified from the output. Output: $($result.StandardOutput)"
    }
}

function Set-C9SentinelOneProtect {
    [CmdletBinding()]
    param()

    $FunctionName = "Set-C9SentinelOneProtect"
    $s1Info = Get-C9SentinelOneInfo
    
    if (-not $s1Info) {
        throw "[$ScriptName - $FunctionName] Cannot protect agent: SentinelOne agent was not found."
    }
    Invoke-C9EndpointCommand -FilePath $s1Info.SentinelCtlPath -ArgumentList "protect"
}

function Get-C9S1ServiceState {
    <#
    .SYNOPSIS
        (Specialist) Checks the existence and status of the four core SentinelOne services.
    .OUTPUTS
        A PSCustomObject with boolean properties for the existence and running state of each service.
    #>
    [CmdletBinding()]
    param()

    $FunctionName = "Get-C9S1ServiceState"
    Write-Host "[$ScriptName - $FunctionName] Checking state of all S1-related Windows services..."

    $serviceState = Invoke-ImmyCommand -ScriptBlock {
        $serviceNames = @(
            "SentinelAgent",
            "SentinelHelperService",
            "SentinelStaticEngine",
            "LogProcessorService"
        )
        $report = [ordered]@{}
        foreach ($name in $serviceNames) {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            $report["Exists_$($name)"] = ($null -ne $service)
            $report["IsRunning_$($name)"] = ($null -ne $service -and $service.Status -eq 'Running')
        }
        return [PSCustomObject]$report
    }

    Write-Host "[$ScriptName - $FunctionName] Service state check complete."
    return $serviceState
}

function Get-C9S1InstallDirectoryState {
    <#
    .SYNOPSIS
        (Specialist) Checks the health of the SentinelOne installation directory.
    .DESCRIPTION
        This function verifies the existence of the installation folder and critical files within it,
        such as SentinelAgent.exe and SentinelCtl.exe.
    .OUTPUTS
        A PSCustomObject detailing the state of the installation directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallPath
    )

    $FunctionName = "Get-C9S1InstallDirectoryState"
    Write-Host "[$ScriptName - $FunctionName] Checking health of install directory: '$InstallPath'..."

    # =========================================================================
    # --- BEGIN CORRECTED SECTION ---
    # =========================================================================
    # We now call Invoke-ImmyCommand WITHOUT -ArgumentList and WITHOUT a param() block inside.
    # We will use the $using: scope modifier, which is the proven, reliable pattern.
    $dirState = Invoke-ImmyCommand -ScriptBlock {
        # The 'param($path)' line has been removed.

        # We now access the Metascript's $InstallPath variable directly using $using:
        $agentExe = Join-Path -Path $using:InstallPath -ChildPath "SentinelAgent.exe"
        $ctlExe = Join-Path -Path $using:InstallPath -ChildPath "SentinelCtl.exe"

        $report = [ordered]@{
            DirectoryExists      = Test-Path -Path $using:InstallPath -PathType Container
            SentinelAgentExists  = Test-Path -Path $agentExe -PathType Leaf
            SentinelCtlExists    = Test-Path -Path $ctlExe -PathType Leaf
        }
        # Define "healthy" as the directory and both key executables existing.
        $report['IsHealthy'] = ($report.DirectoryExists -and $report.SentinelAgentExists -and $report.SentinelCtlExists)

        return [PSCustomObject]$report
    } # Note: The -ArgumentList parameter has been removed.
    # =========================================================================
    # --- END CORRECTED SECTION ---
    # =========================================================================

    Write-Host "[$ScriptName - $FunctionName] Directory health check complete. IsHealthy: $($dirState.IsHealthy)."
    return $dirState
}

function Get-C9S1ComprehensiveStatus {
    <#
    .SYNOPSIS
        (Orchestrator) Gathers a complete, multi-point status report for the SentinelOne agent.
    .DESCRIPTION
        This is the new master "Get" function. It orchestrates calls to multiple specialist functions
        to collect information from WMI, the file system, and sentinelctl.exe. It assembles all
        data into a single, rich object for high-level decision making.
    .OUTPUTS
        A single, rich PSCustomObject containing a full health and status report of the agent.
    #>
    [CmdletBinding()]
    param()

    $FunctionName = "Get-C9S1ComprehensiveStatus"
    Write-Host "================================================================="
    Write-Host "[$ScriptName - $FunctionName] BEGINNING COMPREHENSIVE S1 STATUS CHECK"
    Write-Host "================================================================="

    # Initialize the final report object with a predictable structure.
    $report = [ordered]@{
        # Top-level summary flags
        IsPresent           = $false
        IsConsideredHealthy = $false
        # Data from different sources
        BaseInfo            = $null # From Get-C9SentinelOneInfo
        ServiceState        = $null # From Get-C9S1ServiceState
        DirectoryState      = $null # From Get-C9S1InstallDirectoryState
        SentinelCtlStatus   = $null # From Get-C9SentinelOneStatus
        # Cross-validated versions
        VersionFromService  = $null
        VersionFromCtl      = $null
    }

    # 1. Get base info (service, paths, version). This is our starting point.
    $report.BaseInfo = Get-C9SentinelOneInfo
    $report.VersionFromService = $report.BaseInfo.Version

    # If BaseInfo is null, the agent isn't installed in a detectable way. We can stop.
    if (-not $report.BaseInfo) {
        Write-Warning "[$ScriptName - $FunctionName] Primary check (Get-C9SentinelOneInfo) found no agent. Status check cannot proceed further."
        $report.IsPresent = $false
        return New-Object -TypeName PSObject -Property $report
    }

    $report.IsPresent = $true
    Write-Host "[$ScriptName - $FunctionName] Agent is present. Version (from Service): $($report.VersionFromService). Continuing checks..."

    # 2. Get the state of all four services.
    $report.ServiceState = Get-C9S1ServiceState

    # 3. Get the state of the installation directory.
    $report.DirectoryState = Get-C9S1InstallDirectoryState -InstallPath $report.BaseInfo.InstallPath
    
    # 4. Get the detailed status from sentinelctl.exe.
    $report.SentinelCtlStatus = Get-C9SentinelOneStatus
    
    # 5. Extract the version from the sentinelctl output for easy comparison.
    if ($report.SentinelCtlStatus -and $report.SentinelCtlStatus.Monitor_Build_id) {
        $report.VersionFromCtl = ($report.SentinelCtlStatus.Monitor_Build_id -split '\+')[0].Trim()
    }
    
    # 6. Define the final "IsConsideredHealthy" summary status based on our findings.
    # This is where we codify our definition of a healthy agent.
    $isHealthy = ($report.BaseInfo -and 
                  $report.ServiceState.IsRunning_SentinelAgent -and 
                  $report.DirectoryState.IsHealthy -and
                  $report.SentinelCtlStatus.IsHealthy -and
                  ($report.VersionFromService -eq $report.VersionFromCtl))

    $report.IsConsideredHealthy = $isHealthy

    Write-Host "[$ScriptName - $FunctionName] FINAL HEALTH STATUS: $($report.IsConsideredHealthy)"
    Write-Host "================================================================="

    return New-Object -TypeName PSObject -Property $report
}

Export-ModuleMember -Function *