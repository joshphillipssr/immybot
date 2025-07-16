#Requires -Version 5.1
<#
.SYNOPSIS
    C9S1EndpointTools - A PowerShell module for local SentinelOne agent diagnostics and interaction.
.DESCRIPTION
    This module provides a suite of granular, single-purpose functions to inspect the health and
    configuration of a SentinelOne agent directly on an endpoint. It is designed to run in the
    local System context and contains no cloud-facing or API-related logic.

    All functions are built upon the discoveries from ticket T20250611.0014, ensuring they are
    robust and account for known failure modes. Version 2.0 refactors presence checks into
    atomic functions for more precise analysis by consuming scripts.
.NOTES
    Author:     Josh Phillips (Consulting) & C9.AI
    Created:    07/15/2025
    Version:    2.0.0
#>

# Export all functions so they are available to any script that imports this module.
Export-ModuleMember -Function *

#region Presence Detection Functions (Granular)

function Test-S1ServicePresence {
    <# .SYNOPSIS Checks for the existence of the primary SentinelAgent service. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    return [boolean](Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue)
}

function Test-S1InstallPathPresence {
    <# .SYNOPSIS Checks for the existence of the default S1 installation directory. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    $installPath = Join-Path -Path $env:ProgramFiles -ChildPath 'SentinelOne\Sentinel Agent'
    return Test-Path -Path $installPath
}

function Test-S1UpgradeCodePresence {
    <# .SYNOPSIS Checks for the "ghost state" UpgradeCode registry key. This is a key MSI health indicator. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()
    # The GUID {47529454-1563-479A-8724-5214532589F3} is stored in a reversed format by the Windows Installer.
    $upgradeCodePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\454925743651A974784225413552983F'
    return Test-Path -Path $upgradeCodePath
}

#endregion

#region Health & State Functions

function Get-S1AgentVersion {
    <#
    .SYNOPSIS
        Gets the agent version from the live SentinelAgent.exe file properties.
    .DESCRIPTION
        Uses the battle-tested logic from T20250611.0014 to reliably get the version from the
        running service's executable, avoiding unreliable registry methods and preventing
        PowerShell output stream pollution that can confuse automation engines like ImmyBot.
    .OUTPUTS
        [string] The product version string (e.g., '24.2.3.471') or $null if not found.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        # Query for the service using Get-CimInstance as it's more robust. Suppress its object output.
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
        if (-not $service) { return $null }

        $exePath = $service.PathName.Trim('"')

        # Use -LiteralPath for robustness against special characters.
        if (Test-Path -LiteralPath $exePath) {
            # Get the version directly from the property to avoid outputting the full FileInfo object.
            $version = (Get-Item -LiteralPath $exePath).VersionInfo.ProductVersion
            if ($version) {
                # This is the ONLY thing that should write to the success stream.
                return $version
            }
        }
    }
    catch {
        # On any unexpected/terminating error, return null to signal "not found".
        Write-Warning "An error occurred while getting agent version: $($_.Exception.Message)"
        return $null
    }
    # If any check above fails to return, explicitly return null.
    return $null
}

function Test-S1ServicesAllRunning {
    <# .SYNOPSIS Checks that all required SentinelOne services are present and in a 'Running' state. #>
    [CmdletBinding()]
    [OutputType([boolean])]
    param()

    $s1Services = @(
        'SentinelAgent',
        'SentinelStaticEngine',
        'SentinelHelperService',
        'SentinelLogProcessor'
    )

    foreach ($serviceName in $s1Services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -ne 'Running') {
            Write-Warning "Service check failed: '$serviceName' is not present or not running."
            return $false
        }
    }
    return $true
}

function Get-S1CtlPath {
    <# .SYNOPSIS Finds the full path to the SentinelCtl.exe utility. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctlPath = Join-Path -Path $env:ProgramFiles -ChildPath 'SentinelOne\Sentinel Agent\SentinelCtl.exe'
    if (Test-Path -Path $ctlPath) { return $ctlPath }
    return $null
}

function Get-S1AgentId {
    <# .SYNOPSIS Retrieves the local agent's UUID using SentinelCtl.exe. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$CtlPath)

    # Function logic remains the same...
    if (-not(Test-Path -Path $CtlPath)) { return $null }
    try {
        $agentId = (& $CtlPath agent_id 2>&1).Trim()
        if ($agentId -and $agentId -notlike "*error*") { return $agentId }
        throw "Command returned invalid output: $agentId"
    } catch { return $null }
}

function Get-S1CtlStatus {
    <# .SYNOPSIS Retrieves the full, raw status output from SentinelCtl.exe. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$CtlPath)
    
    # Function logic remains the same...
    if (-not(Test-Path -Path $CtlPath)) { return $null }
    try {
        return (& $CtlPath status 2>&1 | Out-String).Trim()
    } catch { return $null }
}

#endregion

#region Master Function

function Get-S1LocalHealthReport {
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

    $report = [ordered]@{
        # Granular presence checks
        ServiceIsPresent    = Test-S1ServicePresence
        InstallPathExists   = Test-S1InstallPathPresence
        UpgradeCodeExists   = Test-S1UpgradeCodePresence
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

    # If nothing was found, we are done. Return the minimal report.
    if (-not $report.IsPresent) {
        return [PSCustomObject]$report
    }

    # If S1 is present in any form, proceed to gather the rest of the details.
    $report.ServicesAllRunning = Test-S1ServicesAllRunning
    $report.AgentVersion = Get-S1AgentVersion

    $ctlPath = Get-S1CtlPath
    if ($ctlPath) {
        $report.AgentId = Get-S1AgentId -CtlPath $ctlPath
        $report.CtlStatusOutput = Get-S1CtlStatus -CtlPath $ctlPath
    }

    return [PSCustomObject]$report
}

#endregion Master Function