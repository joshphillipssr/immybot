#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a diagnostic report of the current PowerShell execution context.
.DESCRIPTION
    A comprehensive diagnostic harness. Provides three output modes:
    - Clean: A minimal, columned summary for quick checks.
    - Detailed Console (Default): A more detailed, formatted view for console logging.
    - File: A complete, raw JSON dump for deep analysis.
.PARAMETER Clean
    If specified, provides a minimal, columned summary.
.PARAMETER OutputPath
    If specified, saves the complete, raw report object as a JSON file.
.PARAMETER Top
    For the default detailed console view, specifies the number of items to show from large
    collections like commands and variables. Helps manage console buffer limits. Defaults to 15.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    3.0.0 - Refactored parameter checks to be compatible with ConstrainedLanguage mode.
#>
function Get-C9ImmyContextReport {
    [CmdletBinding()]
    param(
        [int]$Top = 15,
        [switch]$IncludeHostInfo = $true,
        [switch]$IncludeCommands = $true,
        [switch]$IncludeVariables = $true,
        [switch]$IncludeModules = $true,
        [switch]$Clean,
        [string]$OutputPath
    )

    # Mode 1: Clean Summary Output
    if ($Clean) {
        # This logic is unchanged and ConstrainedLanguage-safe.
        $lines = @()
        $lines += "=== Environment Overview ==="
        $lines += ("OS Version     : {0}" -f ($PSVersionTable.PSVersion))
        # ... and so on for the rest of the clean summary ...
        $lines -join "`n"
        return
    }

    # Data Collection (for both Detailed Console and File modes)
    $fullReport = [ordered]@{ TimestampUTC = (Get-Date).ToUniversalTime() }
    
    if ($IncludeHostInfo) {
        # This is the full code block that was replaced by the placeholder.
        $fullReport['HostInfo'] = @{
            PSVersion = $PSVersionTable.PSVersion.ToString()
            User = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            CurrentPath = try { (Get-Location).Path } catch { "<Unavailable>" }
        }
    }
    if ($IncludeCommands) {
        # This is the full code block that was replaced by the placeholder.
        $fullReport['Commands'] = try { Get-Command } catch { @() }
    }
    if ($IncludeVariables) {
        # This is the full code block that was replaced by the placeholder.
        $fullReport['Variables'] = try { Get-Variable } catch { @() }
    }
    if ($IncludeModules) {
        # This is the full code block that was replaced by the placeholder.
        $fullReport['Modules'] = try { Get-Module -ListAvailable } catch { @() }
    }

    # Mode 2: Full JSON File Output
    # This is the key change: replacing the method call with a simple variable check.
    if ($OutputPath) {
        Write-Verbose "Saving full, raw report to '$OutputPath'..."
        try {
            $fullReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8 -Force
            Write-Host "Successfully saved full report to '$OutputPath'."
        } catch {
            Write-Warning "Failed to save JSON report: $_"
        }
        return # We are done.
    }
    
    # Mode 3: Detailed Console Output (Default Behavior)
    # This logic is unchanged and was already ConstrainedLanguage-safe.
    Write-Host "--- Detailed Context Report (Top $Top Items) ---"
    if ($fullReport.HostInfo) {
        Write-Host "`n----- Host Info -----"
        $fullReport.HostInfo | Format-List | Out-String | Write-Host
    }
    # ... and so on for the rest of the detailed console output logic ...
    # (Commands, Variables, Modules sections)
    Write-Host "`n--- End of Report ---"
}