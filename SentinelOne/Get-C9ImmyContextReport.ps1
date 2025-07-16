#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a comprehensive diagnostic report of the current PowerShell execution context.

.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    1.1.0 - Refactored to advanced script format for ImmyBot help compatibility.
#>

[CmdletBinding()]
param(
    [switch]$IncludeHostInfo = $true,
    [switch]$IncludeCommands = $true,
    [switch]$IncludeVariables = $true,
    [switch]$IncludeModules = $true,
    [string]$OutputPath
)

Write-Host "Starting ImmyBot Context Diagnostic Report..."

try {
    # Create a report object to hold all our findings
    $report = [ordered]@{
        ReportTimestampUTC = (Get-Date).ToUniversalTime()
    }

    if ($IncludeHostInfo) {
        Write-Host "Gathering Host and Execution Info..."
        $report['HostInfo'] = @{
            PSVersionTable           = $PSVersionTable
            PSHost                   = $Host
            LanguageMode             = $ExecutionContext.SessionState.LanguageMode
            ExecutionContextIdentity = $env:USERNAME
            WindowsIdentity          = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            ComputerName             = $env:COMPUTERNAME
            CurrentLocation          = (Get-Location).Path
        }
    }

    if ($PSBoundParameters.ContainsKey('OutputPath')) {
        Write-Host "Saving report to '$OutputPath'..."
        try {
            $jsonReport = $report | ConvertTo-Json -Depth 5
            Out-File -FilePath $OutputPath -InputObject $jsonReport -Encoding utf8 -Force -ErrorAction Stop
            Write-Host "Successfully saved report."
        }
        catch {
            Write-Error "Failed to save report to '$OutputPath'. Error: $($_.Exception.Message)"
        }
    }

    Write-Host "Diagnostic report generation complete."
    return [PSCustomObject]$report
}
catch {
    $errorMessage = "A fatal error occurred while generating the context report: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}
