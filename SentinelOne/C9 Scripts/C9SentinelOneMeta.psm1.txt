# =================================================================================
# Name:     C9SentinelOneMeta Module
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

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
            # Write-Host "SentinelOne Version $($s1Info.Version) found at $($s1Info.InstallPath)"
        } else {
            Write-Error "SentinelOne agent not found."
        }
    #>
    [CmdletBinding()]
    param()

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Get-C9SentinelOneInfo"
    Write-Host  "[$ScriptName - $FunctionName] Time to go hunting for the SentinelOne agent on the endpoint..."
    $infoObject = Invoke-ImmyCommand -ScriptBlock {
        Write-Host  "[$ScriptName - $FunctionName] I'm inside an Invoke-ImmyCommand script block now...gonna use Get-CimInstance and look for some services..."
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
        if (-not ($service -and $service.PathName)) {
            return $null
        }
        $agentExePath = $service.PathName.Trim('"')
        $installPath = Split-Path -Path $agentExePath
        $sentinelCtlPath = Join-Path -Path $installPath -ChildPath "sentinelctl.exe"
        if (-not (Test-Path -LiteralPath $agentExePath)) {
            return $null
        }
        $fileInfo = Get-Item -LiteralPath $agentExePath
        return [PSCustomObject]@{
            IsInstalled = $true
            Version = $fileInfo.VersionInfo.ProductVersion
            Service = $service
            InstallPath = $installPath
            AgentExePath = $agentExePath
            SentinelCtlPath = $sentinelCtlPath
        }
    }
    if ($infoObject) {
        Write-Host "[$ScriptName - $FunctionName] Oh baby. Successfully retrieved SentinelOne agent info. Version: $($infoObject.Version)" }
    return $infoObject
}

function Get-C9S1ServiceState {
    <#
    .SYNOPSIS
        (Specialist) Gets the existence and running state of the four core S1 services.
    .DESCRIPTION
        This function reports which of the four core S1 services exist and, if they
        do exist, what their current running state is. It returns an array of objects
        with clear 'Existence' and 'RunningState' properties for unambiguous analysis.
    .OUTPUTS
        An array of PSCustomObjects, with 'Service', 'Existence', and 'RunningState' properties.
    #>
    [CmdletBinding()]
    param()

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'  

    $FunctionName = "Get-C9S1ServiceState"

    $ScriptName = "C9SentinelOneMeta"
    Write-Host  "[$ScriptName - $FunctionName] What do you say we use an Invoke-ImmyCommand block and go look for some S1 Services..."
    Write-Host  "[$ScriptName - $FunctionName] Sweet. I'm glad you agree. Let's go..."
    $serviceReportList = Invoke-ImmyCommand -ScriptBlock {
        $serviceNames = @(
            "SentinelAgent"
            "SentinelHelperService"
            "SentinelStaticEngine"
            "LogProcessorService"
        )
        $reportArray = @()
        foreach ($name in $serviceNames) {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            $existence = if ($null -ne $service) {
                "Exists"
            } else {
                "Not Found"
            }
            $runningState = if ($null -ne $service) {
                $service.Status.ToString()
            } else {
                "N/A"
            }
            $serviceObject = New-Object -TypeName PSObject
            Add-Member -InputObject $serviceObject -MemberType NoteProperty -Name 'Service' -Value $name
            Add-Member -InputObject $serviceObject -MemberType NoteProperty -Name 'Existence' -Value $existence
            Add-Member -InputObject $serviceObject -MemberType NoteProperty -Name 'RunningState' -Value $runningState
            $reportArray += $serviceObject
        }
        return $reportArray
    }
    Write-Host  "[$ScriptName - $FunctionName] I've got the service report list right here. Sending it back to you now..."
    return $serviceReportList
}

function Get-C9S1InstallDirectoryState {
    <#
    .SYNOPSIS
        (Specialist) Performs an exhaustive file system state check for all S1 installations.
    .DESCRIPTION
        This function identifies the parent Sentinel* folder and all of its children. It distinguishes
        between the "active" installation folder and any other (potentially orphaned) folders. It provides
        a file count for both the active folder and a sum of all other folders, which is a key
        diagnostic indicator for parallel/broken installations.
    .PARAMETER InstallPath
        The installation path of the currently active agent.
    .OUTPUTS
        An array of PSCustomObjects, formatted to produce a clean, vertical diagnostic report.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallPath
    )

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Get-C9S1InstallDirectoryState"

    Write-Host "[$ScriptName - $FunctionName] I'm going to use an Invoke-ImmyCommand block and go look at the file system..."
    $dirStateReport = Invoke-ImmyCommand -ScriptBlock {
        $activeInstallPath = $using:InstallPath; $reportArray = @()
        Write-Host "[$ScriptName - $FunctionName] Gonna use a try block to see if I can figure out what's going on with: $activeInstallPath...I'll let you know what I found when I'm all finished otherwise this is gonna get noisy..."
        try {
            $parentDir = Split-Path -Path $activeInstallPath -Parent
            $activeChildName = Split-Path -Path $activeInstallPath -Leaf
            $allChildDirs = Get-ChildItem -Path $parentDir -Directory -ErrorAction SilentlyContinue
            $otherChildDirs = $allChildDirs | Where-Object {
                $_.Name -ne $activeChildName
            }
            $activeFolderFileCount = (Get-ChildItem -Path $activeInstallPath -File -Recurse -ErrorAction SilentlyContinue).Count
            $otherFoldersFileCount = 0
            if ($otherChildDirs) {
                foreach ($otherDir in $otherChildDirs) {
                    $otherFoldersFileCount += (Get-ChildItem -Path $otherDir.FullName -File -Recurse -ErrorAction SilentlyContinue).Count
                }
            }
            $row1 = New-Object -TypeName PSObject
            Add-Member -InputObject $row1 'Property' 'Installation Folder (Parent)'
            Add-Member -InputObject $row1 'Value' $parentDir
            $reportArray += $row1
            $row2 = New-Object -TypeName PSObject
            Add-Member -InputObject $row2 'Property' 'Install Folder (Child)'
            Add-Member -InputObject $row2 'Value' $activeChildName
            $reportArray += $row2
            $row3 = New-Object -TypeName PSObject
            Add-Member -InputObject $row3 'Property' 'Number of additional child folders'
            Add-Member -InputObject $row3 'Value' "$($otherChildDirs.Count)"
            $reportArray += $row3
            $row4 = New-Object -TypeName PSObject
            Add-Member -InputObject $row4 'Property' 'Install Folder Total Files'
            Add-Member -InputObject $row4 'Value' "$activeFolderFileCount"
            $reportArray += $row4
            $row5 = New-Object -TypeName PSObject
            Add-Member -InputObject $row5 'Property' 'Other Child Folder Total Files'
            Add-Member -InputObject $row5 'Value' "$($otherFoldersFileCount)"
            $reportArray += $row5
        } catch {
            $errorRow = New-Object -TypeName PSObject
            Add-Member -InputObject $errorRow 'Property' 'FileSystem Analysis'
            Add-Member -InputObject $errorRow 'Value' "Error: $($_.Exception.Message)"
            $reportArray += $errorRow
        }
        return $reportArray
    }
    Write-Host "[$ScriptName - $FunctionName] To be honest, I'm not smart enough to understand everything I found, but here's the (possibly blank) report..."
    return $dirStateReport
}

function Get-C9S1ComprehensiveStatus {
    <#
    .SYNOPSIS
        (S1-Specific Get Orchestrator) Gathers all local SentinelOne agent status data.
    .DESCRIPTION
        This is a master "Get" function for all things related to the local S1 agent. It orchestrates
        calls to specialist functions to get service state, file system state, and sentinelctl status,
        then assembles them into a single, comprehensive data object.
        This function is designed to be "quiet" and return only data, not perform logging itself.
    .OUTPUTS
        A PSCustomObject containing the complete local state of the SentinelOne agent.
    #>
    [CmdletBinding()]
    param()

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Get-C9S1ComprehensiveStatus"

    Write-Host  "[$ScriptName - $FunctionName] We're gonna do something I like to call...gettin' a ton of SentinelOne info..."
    $s1Data = [ordered]@{
        IsPresentAnywhere = $false
        VersionFromService = $null
        VersionFromCtl = $null
        AgentId = $null
        InstallPath = $null
        ServicesReport = $null
        InstallDirectoryReport = $null
        SentinelCtlStatusReport = $null
    }
    $baseInfo = Get-C9SentinelOneInfo
    if (-not $baseInfo) {
        Write-Warning "[$ScriptName - $FunctionName] No S1 agent found. Returning empty report."
        return New-Object -TypeName PSObject -Property $s1Data
    }
    Write-Host  "[$ScriptName - $FunctionName] Found the SentinelOne agent. Let's gather all the details now..."
    $s1Data.IsPresentAnywhere  = $true
    $s1Data.VersionFromService = $baseInfo.Version
    $s1Data.InstallPath = $baseInfo.InstallPath
    Write-Host  "[$ScriptName - $FunctionName] Now I'm gonna call some helper functions take us to some other places to get more stuff..."
    $s1Data.ServicesReport = Get-C9S1ServiceState
    $s1Data.InstallDirectoryReport = Get-C9S1InstallDirectoryState -InstallPath $baseInfo.InstallPath
    $ctlStatusReport = Get-C9SentinelCtl -Command "status"
    $s1Data.SentinelCtlStatusReport = $ctlStatusReport
    $ctlVersionLine = $ctlStatusReport | Where-Object {
        $_.Property -eq 'Monitor Build id'
    } | Select-Object -First 1
    if ($ctlVersionLine) {
        $s1Data.VersionFromCtl = ($ctlVersionLine.Value -split '\+')[0].Trim()
    }
    $ctlAgentIdReport = Get-C9SentinelCtl -Command "agent_id"
    $agentIdLine = $ctlAgentIdReport | Where-Object {
        $_.Property -eq 'Agent ID'
    } | Select-Object -First 1
    if ($agentIdLine) {
        $s1Data.AgentId = $agentIdLine.Value
    }
    Write-Host  "[$ScriptName - $FunctionName] We're done. I think we did good. Here's the final report object..."
    return New-Object -TypeName PSObject -Property $s1Data
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
            # Write-Host "Detected SentinelOne Version: $installedVersion"
        } else {
            Write-Warning "Could not detect an installed SentinelOne agent."
        }
    #>

    [CmdletBinding()]
    param()

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Get-C9SentinelOneVersion"

    # Write-Host "[$ScriptName - $FunctionName] Attempting to get S1 version from endpoint..."
    
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
        Author:     Josh Phillips
        Created:    07/15/2025
        Version:    2.0.0
    #>

    param()

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Get-C9S1EndpointData"

    try {
        # The #Requires statement above handles the import of our custom module.
        # We can use # Write-Host for high-level status messages that are always visible in ImmyBot logs.
        # Write-Host "[$ScriptName - $FunctionName] Executing SentinelOne Health 'Get' script."
        # Write-Host "[$ScriptName - $FunctionName] This script gathers raw data for inventory or for a 'Test' script to evaluate."

        # Call the master function from our module. It handles all its own detailed logging.
        # The output of this function is the final return value of this script.
        $healthReport = Get-C9S1LocalHealthReport

        Write-Host "[$ScriptName - $FunctionName] Successfully generated health report. Returning data object."
        
        # Returning the object is the last action. ImmyBot will capture this.
        return $healthReport
    } catch {
        # If anything goes wrong (e.g., module not found, catastrophic function error),
        # write a clear error and re-throw to ensure ImmyBot registers the failure.
        $errorMessage = "A fatal error occurred in Get-S1Health.ps1: $($_.Exception.Message)"
        Write-Error $errorMessage
        throw $errorMessage
    }
}

function Get-C9SentinelCtl {
    <#
    .SYNOPSIS
        (Specialist) A generic wrapper for executing sentinelctl.exe commands and returning a clean data report.
    .DESCRIPTION
        This function runs any specified sentinelctl.exe command. It is "quiet" by design,
        performing its work and returning a structured array of objects without verbose logging.
        The calling script is responsible for logging the results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Get-C9SentinelCtl"

    Write-Host  "[$ScriptName - $FunctionName] I'm going to go look for SentinelCtl on the endpoint so I can run the command: $Command..."
    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info -or -not $s1Info.SentinelCtlPath) {
        return $null
    }
    $sentinelCtlPath = $s1Info.SentinelCtlPath
    if (-not (Invoke-ImmyCommand -ScriptBlock {
        Test-Path $using:sentinelCtlPath })) { return $null }
    $ctlResult = Invoke-C9EndpointCommand -FilePath $sentinelCtlPath -ArgumentList $Command
    Write-Host "[$ScriptName - $FunctionName] Found it. Did it. Here you go: $($ctlResult.StandardOutput.Trim())"
    Write-Host "[$ScriptName - $FunctionName] Almost forgot to mention...if you are wondering how I can do something so cool on an endpoint from the metascript context, check out Invoke-C9EndpointCommand in the C9MetascriptHelpers module..."
    
    $reportArray = @()

    $exitCodeObject = New-Object -TypeName PSObject
    Add-Member -InputObject $exitCodeObject -MemberType NoteProperty -Name 'Property' -Value 'Execution Exit Code'
    Add-Member -InputObject $exitCodeObject -MemberType NoteProperty -Name 'Value' -Value "$($ctlResult.ExitCode)"
    
    $reportArray += $exitCodeObject
    
    $successObject = New-Object -TypeName PSObject
    Add-Member -InputObject $successObject -MemberType NoteProperty -Name 'Property' -Value 'Execution Was Successful'
    Add-Member -InputObject $successObject -MemberType NoteProperty -Name 'Value' -Value ($ctlResult.ExitCode -eq 0)
    
    $reportArray += $successObject
    
    switch ($Command) {
        "status" {
            $outputLines = $ctlResult.StandardOutput -split '(?:\r\n|\r|\n)'
            foreach ($line in $outputLines) {
                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }
                $rowObject = New-Object PSObject
                $key = ""
                $value = ""
                if ($line -like '*:*') {
                    $key, $value = $line.Split(':', 2)
                } elseif ($line -like '* is loaded') {
                    $parts = $line -split ' is loaded'
                    $key = "$($parts[0]) State"
                    $value = "loaded"
                } elseif ($line -like '* is running as *') {
                    $parts = $line -split ' is running as '
                    $key = "$($parts[0]) Running State"
                    $value = $parts[1]
                } else {
                    $key = "Uncategorized Status"
                    $value = $line
                }
                Add-Member -InputObject $rowObject -MemberType NoteProperty -Name 'Property' -Value $key.Trim()
                Add-Member -InputObject $rowObject -MemberType NoteProperty -Name 'Value' -Value $value.Trim()
                $reportArray += $rowObject
            }
        }
        "agent_id" {
            $rowObject = New-Object PSObject
            Add-Member -InputObject $rowObject -MemberType NoteProperty -Name 'Property' -Value 'Agent ID'
            Add-Member -InputObject $rowObject -MemberType NoteProperty -Name 'Value' -Value $ctlResult.StandardOutput.Trim()
            $reportArray += $rowObject
        }
        default {
            $rowObject = New-Object PSObject
            Add-Member -InputObject $rowObject -MemberType NoteProperty -Name "Property" -Value "Output from '$Command'"
            Add-Member -InputObject $rowObject -MemberType NoteProperty -Name "Value" -Value $ctlResult.StandardOutput.Trim()
            $reportArray += $rowObject
        }
    }
    Write-Host "[$ScriptName - $FunctionName] Here's the report array I made for you. I'm out!"
    return $reportArray
}

function Test-C9S1LocalUpgradeAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AgentId
    )

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Test-C9S1LocalUpgradeAuthorization"

    $endpoint = "agents/$AgentId/local-upgrade-authorization"
    # Write-Host "[$ScriptName - $FunctionName] Checking API endpoint '$endpoint' for agent protection status."

    try {
        # We expect a successful call to return data with an 'enabled' property.
        $response = Invoke-C9S1RestMethod -Endpoint $endpoint
        
        # The API returns { "data": { "enabled": true/false } } on success
        if ($null -ne $response.enabled -and $response.enabled) {
            # Write-Host "[$ScriptName - $FunctionName] API Response: Local upgrade authorization is ENABLED."
            return $true
        } else {
            # Write-Host "[$ScriptName - $FunctionName] API Response: Local upgrade authorization is DISABLED."
            return $false
        }
    } catch {
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

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Test-S1InstallPreFlight"

    # Write-Host "[$ScriptName - $FunctionName] Starting SentinelOne installation pre-flight check..."

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
            } else {
                 return [PSCustomObject]@{
                    ShouldStop = $false
                    Reason     = 'Agent is online and not protected by a local upgrade policy. Proceeding with workflow.'
                }
            }
        } catch {
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
    } catch {
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

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

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
    # Write-Host "[$ScriptName - $FunctionName] [RESOLVE] Downloading '$FileName' to endpoint path '$destinationPath'..."
    # The '-Headers' parameter is the critical addition for authenticated downloads.
    Download-File -Url $DownloadUrl -OutFile $destinationPath -Headers $AuthHeader
    # Write-Host "[$ScriptName - $FunctionName] [RESOLVE] SUCCESS: File downloaded."
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

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Set-C9SentinelOneUnprotect"

    # Step 1: Find the agent using our helper function
    # Write-Host "[$ScriptName - $FunctionName] Attempting to locate the SentinelOne agent..."
    $s1Info = Get-C9SentinelOneInfo
    if (-not $s1Info) {
        throw "[$ScriptName - $FunctionName] Cannot unprotect agent: SentinelOne agent was not found on the endpoint."
    }

    # Step 2: Prepare and execute the command using our robust command wrapper
    # Write-Host "[$ScriptName - $FunctionName] Disabling SentinelOne agent protection via sentinelctl..."
    $argumentList = "unprotect", "-k", $Passphrase
    $result = Invoke-C9EndpointCommand -FilePath $s1Info.SentinelCtlPath -ArgumentList $argumentList

    # Step 3: Intelligent Error Handling
    if ($result.ExitCode -ne 0) {
        throw "[$ScriptName - $FunctionName] Failed to unprotect SentinelOne agent. The sentinelctl.exe process returned exit code: $($result.ExitCode). Error Output: $($result.StandardError)"
    }
    
    # Ignore known, benign warnings from sentinelctl.exe
    if ($result.StandardError -and $result.StandardError -notmatch 'In-Process Client') {
        throw "[$ScriptName - $FunctionName] An unexpected error was reported by sentinelctl.exe during unprotect: $($result.StandardError)"
    }
    
    # Step 4: Final validation
    if ($result.StandardOutput -match 'Protection is off|Protection disabled') {
        Write-Host "[$ScriptName - $FunctionName] [SUCCESS] SentinelOne agent protection has been successfully disabled."
        return $true
    } else {
        throw "[$ScriptName - $FunctionName] Unprotect command completed, but success could not be verified from the output. Output: $($result.StandardOutput)"
    }
}

function Set-C9SentinelOneProtect {
    [CmdletBinding()]
    param()

    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'

    $FunctionName = "Set-C9SentinelOneProtect"
    $s1Info = Get-C9SentinelOneInfo
    
    if (-not $s1Info) {
        throw "[$ScriptName - $FunctionName] Cannot protect agent: SentinelOne agent was not found."
    }
    Invoke-C9EndpointCommand -FilePath $s1Info.SentinelCtlPath -ArgumentList "protect"
}

function Invoke-C9S1StandardUninstall {
    <#
    .SYNOPSIS
        (Action) Performs the standard, vendor-recommended uninstall using the modern installer's clean command.
    .DESCRIPTION
        This is now our primary removal method. It follows the proven "SCCM Hybrid" model by copying
        the main installer to a temporary directory on the endpoint before executing it with the '-c' (clean)
        argument. It uses the robust Invoke-C9InstallWithChildProcesses helper to manage the process.
    .PARAMETER CloudCredentials
        The CloudCredentials object containing the SiteToken.
    .PARAMETER InstallerFile
        The full path to the main SentinelOneInstaller*.exe file provided by the ImmyBot platform.
    .OUTPUTS
        A PSCustomObject with a boolean 'Success' property and a 'Reason' string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$CloudCredentials,
        
        [Parameter(Mandatory = $true)]
        [string]$InstallerFile
    )
    $FunctionName = "Invoke-C9S1StandardUninstall"
    Write-Host "[$ScriptName - $FunctionName] Starting standard uninstall using SentinelOneInstaller.exe -c..."

    # Create a temporary directory on the endpoint.
    $tempDirOnEndpoint = Invoke-ImmyCommand -ScriptBlock {
        $tempPath = Join-Path -Path $env:TEMP -ChildPath "S1_StandardUninstall_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
        return $tempPath
    }

    try {
        # --- Step 1: Copy Installer to Temp Dir (SCCM Hybrid Pattern) ---
        $copiedInstallerPath = Join-Path -Path $tempDirOnEndpoint -ChildPath (Split-Path $InstallerFile -Leaf)
        Write-Host "[$ScriptName - $FunctionName] Copying installer to '$copiedInstallerPath' on endpoint..."
        Invoke-ImmyCommand -ScriptBlock { Copy-Item -Path $using:InstallerFile -Destination $using:copiedInstallerPath -Force }

        # --- Step 2: Execute the Cleaner Command ---
        $cleanerArgs = "-c -q" # Always run clean and quiet
        if ($CloudCredentials.HasSiteToken) {
            $cleanerArgs += " -t `"$($CloudCredentials.SiteToken)`""
            Write-Host "[$ScriptName - $FunctionName] Executing cleaner with site token..."
        } else {
            Write-Warning "[$ScriptName - $FunctionName] No site token available. Running cleaner without it."
        }
        
        $cleanerResult = Invoke-C9InstallWithChildProcesses -Path $copiedInstallerPath -Arguments $cleanerArgs -TimeoutInSeconds 900

        if ($cleanerResult.ExitCode -ne 0 -and $cleanerResult.ExitCode -ne 1605) {
            throw "The installer clean process failed with Exit Code: $($cleanerResult.ExitCode). Error: $($cleanerResult.StandardError)"
        }

        Write-Host "[$ScriptName - $FunctionName] [SUCCESS] Standard uninstall process completed (Exit Code: $($cleanerResult.ExitCode))."
        return [PSCustomObject]@{ Success = $true; Reason = "Standard uninstall completed successfully." }

    } catch {
        $errorMessage = "Standard uninstall failed. Reason: $($_.Exception.Message)"
        Write-Error "[$ScriptName - $FunctionName] [FAIL] $errorMessage"
        return [PSCustomObject]@{ Success = $false; Reason = $errorMessage }
    } finally {
        if ($tempDirOnEndpoint) {
            Write-Host "[$ScriptName - $FunctionName] Cleaning up temporary directory: $tempDirOnEndpoint"
            Invoke-ImmyCommand { Remove-Item -Path $using:tempDirOnEndpoint -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Invoke-C9S1ForcedRemoval {
    <#
    .SYNOPSIS
        (Action) Performs a forced, aggressive removal using the legacy SentinelCleaner.exe utility.
    .DESCRIPTION
        This is our "nuclear option" for the most stubborn agents. It uses the Get-C9Portable7za helper
        to extract the legacy 'SentinelCleaner.exe' from the main installer package and then executes it.
    .PARAMETER CloudCredentials
        The CloudCredentials object, checked for a site token which may be used by the cleaner.
    .PARAMETER InstallerFile
        The full path to the main SentinelOneInstaller*.exe file, which contains the cleaner.
    .OUTPUTS
        A PSCustomObject with a boolean 'Success' property and a 'Reason' string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$CloudCredentials,
        
        [Parameter(Mandatory = $true)]
        [string]$InstallerFile
    )
    $FunctionName = "Invoke-C9S1ForcedRemoval"
    Write-Host "[$ScriptName - $FunctionName] Starting forced removal process using legacy SentinelCleaner.exe..."

    $tempDirOnEndpoint = Invoke-ImmyCommand -ScriptBlock {
        $tempPath = Join-Path -Path $env:TEMP -ChildPath "S1_ForcedRemoval_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
        return $tempPath
    }

    try {
        # --- Step 1: Get the 7-Zip utility (Proven Pattern) ---
        $7zaPath = Get-C9Portable7za
        if (-not $7zaPath) { throw "Could not acquire the 7za.exe utility." }

        # --- Step 2: Extract SentinelCleaner.exe ---
        Write-Host "[$ScriptName - $FunctionName] Extracting SentinelCleaner.exe from '$InstallerFile'..."
        $cleanerPathOnEndpoint = Join-Path -Path $tempDirOnEndpoint -ChildPath "SentinelCleaner.exe"
        
        Invoke-ImmyCommand -ScriptBlock {
            & $using:7zaPath x $using:InstallerFile -o$using:tempDirOnEndpoint SentinelCleaner.exe | Out-Null
        }

        if (-not (Invoke-ImmyCommand { Test-Path $using:cleanerPathOnEndpoint })) {
            throw "Failed to extract SentinelCleaner.exe from the installer package."
        }
        Write-Host "[$ScriptName - $FunctionName] [SUCCESS] Extracted cleaner to '$cleanerPathOnEndpoint'."

        # --- Step 3: Execute the Legacy Cleaner ---
        $cleanerResult = Invoke-C9InstallWithChildProcesses -Path $cleanerPathOnEndpoint -TimeoutInSeconds 900

        if ($cleanerResult.ExitCode -ne 0) {
            throw "The SentinelCleaner.exe process failed with Exit Code: $($cleanerResult.ExitCode). Error: $($cleanerResult.StandardError)"
        }

        Write-Host "[$ScriptName - $FunctionName] [SUCCESS] Forced removal process completed."
        return [PSCustomObject]@{ Success = $true; Reason = "Forced removal with legacy cleaner completed successfully." }

    } catch {
        $errorMessage = "Forced removal failed. Reason: $($_.Exception.Message)"
        Write-Error "[$ScriptName - $FunctionName] [FAIL] $errorMessage"
        return [PSCustomObject]@{ Success = $false; Reason = $errorMessage }
    } finally {
        if ($tempDirOnEndpoint) {
            Write-Host "[$ScriptName - $FunctionName] Cleaning up temporary directory: $tempDirOnEndpoint"
            Invoke-ImmyCommand { Remove-Item -Path $using:tempDirOnEndpoint -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Export-ModuleMember -Function *