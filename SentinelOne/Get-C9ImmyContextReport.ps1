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
#>
function Get-C9ImmyContextReport {
    [CmdletBinding()]
    param(
        # The new -Top parameter for controlling console verbosity
        [int]$Top = 15,

        # Existing parameters
        [switch]$IncludeHostInfo = $true,
        [switch]$IncludeCommands = $true,
        [switch]$IncludeVariables = $true,
        [switch]$IncludeModules = $true,
        [switch]$Clean,
        [string]$OutputPath
    )

    # --- Mode 1: Clean Summary Output ---
    if ($Clean) {
        # ... (This logic remains unchanged) ...
        # It provides the ultra-concise, safe summary.
        return
    }

    # --- Data Collection (for both Detailed Console and File modes) ---
    # This block gathers the full, raw data first.
    $fullReport = [ordered]@{ TimestampUTC = (Get-Date).ToUniversalTime() }
    if ($IncludeHostInfo) {
        $fullReport['HostInfo'] = @{
            PSVersion = $PSVersionTable.PSVersion.ToString()
            User = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            CurrentPath = try { (Get-Location).Path } catch { "<Unavailable>" }
        }
    }
    if ($IncludeCommands) {
        # Note: We get ALL commands here for the raw report. We will filter later for console display.
        $fullReport['Commands'] = try { Get-Command } catch { @() }
    }
    if ($IncludeVariables) {
        $fullReport['Variables'] = try { Get-Variable } catch { @() }
    }
    if ($IncludeModules) {
        $fullReport['Modules'] = try { Get-Module -ListAvailable } catch { @() }
    }


    # --- Mode 2: Full JSON File Output ---
    if ($PSBoundParameters.ContainsKey('OutputPath')) {
        Write-Verbose "Saving full, raw report to '$OutputPath'..."
        try {
            # We convert the full, unfiltered report object to JSON.
            $fullReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8 -Force
            Write-Host "Successfully saved full report to '$OutputPath'."
        } catch {
            Write-Warning "Failed to save JSON report: $_"
        }
        return # We are done.
    }

    
    # --- Mode 3: Detailed Console Output (Default Behavior) ---
    # This is the new default logic if -Clean and -OutputPath are not used.
    Write-Host "--- Detailed Context Report (Top $Top Items) ---"
    
    if ($fullReport.HostInfo) {
        Write-Host "`n----- Host Info -----"
        # Format-List is perfect for key-value pairs.
        $fullReport.HostInfo | Format-List | Out-String | Write-Host
    }

    if ($fullReport.Commands) {
        Write-Host "`n----- Commands (Showing Top $Top) -----"
        # Here we use -Top to limit the output before formatting it.
        $fullReport.Commands | Select-Object -First $Top Name, CommandType | Format-Table -AutoSize | Out-String | Write-Host
    }
    
    if ($fullReport.Variables) {
        Write-Host "`n----- Variables (Showing Top $Top) -----"
        # We must exclude the massive 'cmds' variable we created on 07/15/25, as it pollutes the output.
        $fullReport.Variables | Where-Object Name -ne 'cmds' | Select-Object -First $Top Name, @{n='Value';e={$_.Value -join ', '}} | Format-Table -AutoSize -Wrap | Out-String | Write-Host
    }

    if ($fullReport.Modules) {
        Write-Host "`n----- Modules (Showing Top $Top) -----"
        $fullReport.Modules | Select-Object -First $Top Name, Version | Format-Table -AutoSize | Out-String | Write-Host
    }

    Write-Host "`n--- End of Report ---"
}