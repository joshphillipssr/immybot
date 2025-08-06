#Requires -Version 5.1
<#
.SYNOPSIS
    C9S1EndpointTools - A PowerShell module for local SentinelOne agent diagnostics and interaction.
.DESCRIPTION
    This module provides a suite of granular, single-purpose functions to inspect the health and
    configuration of a SentinelOne agent directly on an endpoint. It is designed to run in the
    local System context and contains no cloud-facing or API-related logic.

    All functions are prefixed with 'C9-' to denote they are part of the Cloud 9 custom library.
    Functions are organized by verb (Get, Test) for clarity and maintainability.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    3.0.0
#>

# Export all functions so they are available to any script that imports this module.

#region Test Functions (Return Boolean)
#==================================================================================================

function Test-C9S1ServicePresence {
    <# .SYNOPSIS Checks for the existence of the primary SentinelAgent service. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    Write-Verbose "Testing for presence of 'SentinelAgent' service..."
    $isPresent = [boolean](Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue)
    Write-Verbose "Service presence check result: $isPresent"
    return $isPresent
}

function Test-C9S1InstallPathPresence {
    <# .SYNOPSIS Checks for the existence of the default S1 installation directory. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    $installPath = Join-Path -Path $env:ProgramFiles -ChildPath 'SentinelOne\Sentinel Agent'
    Write-Verbose "Testing for presence of install path: '$installPath'..."
    $isPresent = Test-Path -Path $installPath
    Write-Verbose "Install path presence check result: $isPresent"
    return $isPresent
}

function Test-C9S1UpgradeCodePresence {
    <# .SYNOPSIS Checks for the "ghost state" UpgradeCode registry key. This is a key MSI health indicator. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    # The GUID {47529454-1563-479A-8724-5214532589F3} is stored in a reversed format by the Windows Installer.
    $upgradeCodePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\454925743651A974784225413552983F'
    Write-Verbose "Testing for presence of UpgradeCode registry key..."
    $isPresent = Test-Path -Path $upgradeCodePath
    Write-Verbose "UpgradeCode presence check result: $isPresent"
    return $isPresent
}

function Test-C9S1ServicesAllRunning {
    <# .SYNOPSIS Checks that all required SentinelOne services are present and in a 'Running' state. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    Write-Verbose "Testing if all required S1 services are running..."
    $s1Services = @(
        'SentinelAgent',
        'SentinelStaticEngine',
        'SentinelHelperService',
        'SentinelLogProcessor'
    )
    foreach ($serviceName in $s1Services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Warning "Service check [FAIL]: '$serviceName' is not installed."
            return $false
        }
        if ($service.Status -ne 'Running') {
            Write-Warning "Service check [FAIL]: '$serviceName' is present but status is '$($service.Status)'."
            return $false
        }
        Write-Verbose "Service check [PASS]: '$serviceName' is running."
    }
    Write-Verbose "All required SentinelOne services are confirmed running."
    return $true
}

#endregion Test Functions

#region Get Functions (Return Data)
#==================================================================================================

function Get-C9S1AgentVersion {
    <# .SYNOPSIS Gets the agent version from the live SentinelAgent.exe file properties. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    Write-Verbose "Attempting to get agent version from running service executable..."
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Verbose "Agent version not found: 'SentinelAgent' service does not exist."
            return $null
        }
        $exePath = $service.PathName.Trim('"')
        if (Test-Path -LiteralPath $exePath) {
            $version = (Get-Item -LiteralPath $exePath).VersionInfo.ProductVersion
            if ($version) {
                Write-Verbose "Successfully retrieved agent version '$version' from '$exePath'."
                return $version
            }
        }
    }
    catch {
        Write-Warning "An error occurred while getting agent version: $($_.Exception.Message)"
        return $null
    }
    Write-Verbose "Agent version could not be determined."
    return $null
}

function Get-C9S1CtlPath {
    <# .SYNOPSIS Finds the full path to the SentinelCtl.exe utility. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $ctlPath = Join-Path -Path $env:ProgramFiles -ChildPath 'SentinelOne\Sentinel Agent\SentinelCtl.exe'
    Write-Verbose "Checking for SentinelCtl.exe at '$ctlPath'..."
    if (Test-Path -Path $ctlPath) {
        Write-Verbose "SentinelCtl.exe found."
        return $ctlPath
    }
    Write-Verbose "SentinelCtl.exe not found."
    return $null
}

function Get-C9S1AgentId {
    <# .SYNOPSIS Retrieves the local agent's UUID using SentinelCtl.exe. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$CtlPath)
    Write-Verbose "Attempting to get Agent ID via SentinelCtl..."
    if (-not(Test-Path -Path $CtlPath)) {
        Write-Warning "Cannot get Agent ID because SentinelCtl.exe was not found."
        return $null
    }
    try {
        $agentId = (& $CtlPath agent_id 2>&1).Trim()
        if ($agentId -and $agentId -notlike "*error*") {
            Write-Verbose "Retrieved Agent ID: $agentId"
            return $agentId
        }
        throw "Command returned invalid output: $agentId"
    } catch {
        Write-Warning "Failed to execute 'SentinelCtl.exe agent_id': $($_.Exception.Message)"
        return $null
    }
}

function Get-C9S1CtlStatus {
    <# .SYNOPSIS Retrieves the full, raw status output from SentinelCtl.exe. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$CtlPath)
    Write-Verbose "Attempting to get full status output via SentinelCtl..."
    if (-not(Test-Path -Path $CtlPath)) {
        Write-Warning "Cannot get Ctl Status because SentinelCtl.exe was not found."
        return $null
    }
    try {
        $statusOutput = (& $CtlPath status 2>&1 | Out-String).Trim()
        Write-Verbose "Successfully retrieved status from SentinelCtl.exe."
        return $statusOutput
    } catch {
        Write-Warning "Failed to execute 'SentinelCtl.exe status': $($_.Exception.Message)"
        return $null
    }
}

#endregion Get Functions

#region Master Orchestrator Function
#==================================================================================================

function Get-C9S1LocalHealthReport {
    <#
    .SYNOPSIS
        The primary public function. Gathers a comprehensive and granular health report.
    .DESCRIPTION
        This function calls all the atomic helper functions to build and return a rich PSCustomObject
        containing detailed raw health data about the local SentinelOne agent. This rich object is
        ideal for detailed analysis in a 'Test' script.
    .OUTPUTS
        [PSCustomObject] An object containing all collected health data points.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Host "--- Generating Local SentinelOne Health Report ---"

    $report = [ordered]@{
        # Granular presence checks
        ServiceIsPresent    = Test-C9S1ServicePresence -Verbose:$false
        InstallPathExists   = Test-C9S1InstallPathPresence -Verbose:$false
        UpgradeCodeExists   = Test-C9S1UpgradeCodePresence -Verbose:$false
        # High-level summary flag
        IsPresent           = $false
        # Detailed health metrics
        ServicesAllRunning  = $false
        AgentVersion        = $null
        AgentId             = $null
        CtlStatusOutput     = $null
    }

    # Set the summary 'IsPresent' flag if any artifact was found.
    $report.IsPresent = ($report.ServiceIsPresent -or $report.InstallPathExists -or $report.UpgradeCodeExists)

    if (-not $report.IsPresent) {
        Write-Host "Conclusion: No SentinelOne artifacts found on this endpoint."
        return [PSCustomObject]$report
    }

    Write-Host "SentinelOne artifacts were found. Proceeding with detailed health checks."
    
    # If S1 is present in any form, proceed to gather the rest of the details.
    $report.ServicesAllRunning = Test-C9S1ServicesAllRunning -Verbose:$false
    $report.AgentVersion = Get-C9S1AgentVersion -Verbose:$false

    $ctlPath = Get-C9S1CtlPath -Verbose:$false
    if ($ctlPath) {
        $report.AgentId = Get-C9S1AgentId -CtlPath $ctlPath -Verbose:$false
        $report.CtlStatusOutput = Get-C9S1CtlStatus -CtlPath $ctlPath -Verbose:$false
    }
    else {
        Write-Warning "SentinelCtl.exe not found. Agent ID and Ctl Status will be null."
    }

    Write-Host "--- Local Health Report Generation Complete ---"
    return [PSCustomObject]$report
}

function Get-C9S1AgentIdFromEndpoint {
    <#
    .SYNOPSIS
        Dynamically finds the SentinelCtl.exe path and uses it to retrieve the agent's UUID.
    .DESCRIPTION
        This function uses the proven logic from the original detection script (T20250701) to
        reliably locate the running agent's executable. It then derives the installation
        directory from that path to construct the correct path to SentinelCtl.exe, even if
        it's inside a versioned folder. Finally, it executes the utility to get the agent ID.
        This is the definitive, endpoint-local method for identifying the agent.
    .OUTPUTS
        [string] The agent UUID, or $null if not found.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        # Use Get-CimInstance to find the service, as proven reliable on 07/01/25.
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
        if (-not $service) { return $null }

        # Get the path to the running executable.
        $exePath = $service.PathName.Trim('"')
        if (-not (Test-Path -LiteralPath $exePath)) { return $null }

        # This is the key insight: derive the installation directory from the running .exe.
        $installDir = Split-Path -Path $exePath -Parent
        $ctlPath = Join-Path -Path $installDir -ChildPath "SentinelCtl.exe"

        if (-not (Test-Path -LiteralPath $ctlPath)) { return $null }

        # Execute SentinelCtl.exe to get the agent ID, as proven reliable on 07/01/25.
        $agentId = (& $ctlPath agent_id 2>&1).Trim()

        # Validate the output to ensure it's a real ID and not an error message.
        if ($agentId -and $agentId -notlike "*error*") {
            # This is the ONLY thing that should write to the success stream.
            return $agentId
        }
    }
    catch {
        # On any unexpected/terminating error, return null to signal "not found".
        Write-Warning "An error occurred while getting agent ID from endpoint: $($_.Exception.Message)"
        return $null
    }
    return $null
}

Export-ModuleMember -Function *