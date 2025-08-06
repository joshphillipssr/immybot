#Requires -Version 5.1
<#
.SYNOPSIS
    A diagnostic harness for the ImmyBot "Cloud Script" context, hardened for ConstrainedLanguage mode.
.DESCRIPTION
    This script is designed to be run as a Cloud Script to generate a comprehensive report
    on its execution environment. It is fully compatible with PowerShell's ConstrainedLanguage
    mode, avoiding the creation of complex .NET types like ArrayList.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    2.0.0 - ConstrainedLanguage Hardened
#>

# This script runs entirely in the server-side Cloud Script context.

$VerbosePreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$report = New-Object -TypeName PSObject

try {
    # --- Phase 1: Environment & Language Mode ---
    Write-Verbose "Phase 1: Gathering Environment Information..."
    $envInfo = New-Object -TypeName PSObject
    try {
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'LanguageMode' -Value $ExecutionContext.SessionState.LanguageMode
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'PSVersionTable' -Value $PSVersionTable
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'OS' -Value $env:OS
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'PSModulePath' -Value ($env:PSModulePath -split ':')
    } catch {
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'Error' -Value "Failed to gather environment info: $($_.Exception.Message)"
    }
    Add-Member -InputObject $report -MemberType NoteProperty -Name 'EnvironmentInfo' -Value $envInfo


    # --- Phase 2: Variable Inspection ---
    Write-Verbose "Phase 2: Inspecting all available variables..."
    # CHANGE: Replaced the incompatible New-Object call with a ConstrainedLanguage-safe array.
    $varList = @()
    try {
        $allVars = Get-Variable
        foreach ($var in $allVars) {
            $varDetail = New-Object -TypeName PSObject
            Add-Member -InputObject $varDetail -MemberType NoteProperty -Name 'Name' -Value $var.Name
            Add-Member -InputObject $varDetail -MemberType NoteProperty -Name 'Value' -Value ($var.Value | Out-String -Stream)
            # CHANGE: Use the += operator to add to the array.
            $varList += $varDetail
        }
    } catch {
        $varList += "Failed to enumerate variables: $($_.Exception.Message)"
    }
    Add-Member -InputObject $report -MemberType NoteProperty -Name 'AvailableVariables' -Value $varList


    # --- Phase 3: Integration Context Deep Dive ---
    Write-Verbose "Phase 3: Performing a deep dive on `$IntegrationContext..."
    $contextDetail = New-Object -TypeName PSObject
    try {
        if (Get-Variable -Name 'IntegrationContext' -ErrorAction SilentlyContinue) {
            Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name 'Exists' -Value $true
            foreach ($key in $IntegrationContext.Keys) {
                Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name $key -Value $IntegrationContext[$key]
            }
        } else {
            Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name 'Exists' -Value $false
        }
    } catch {
        Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name 'Error' -Value "Failed to inspect `$IntegrationContext: $($_.Exception.Message)"
    }
    Add-Member -InputObject $report -MemberType NoteProperty -Name 'IntegrationContextDetail' -Value $contextDetail


    # --- Phase 4: Module Import Test ---
    Write-Verbose "Phase 4: Attempting to import C9SentinelOne.psm1 module..."
    $moduleInfo = New-Object -TypeName PSObject
    try {
        Import-Module C9SentinelOne -ErrorAction Stop
        Add-Member -InputObject $moduleInfo -MemberType NoteProperty -Name 'ImportResult' -Value 'Success'
        $importedCommands = Get-Command -Module C9SentinelOne | Select-Object -ExpandProperty Name
        Add-Member -InputObject $moduleInfo -MemberType NoteProperty -Name 'ExportedCommands' -Value $importedCommands
    } catch {
        Add-Member -InputObject $moduleInfo -MemberType NoteProperty -Name 'ImportResult' -Value 'Failure'
        Add-Member -InputObject $moduleInfo -MemberType NoteProperty -Name 'Error' -Value "Failed to import module: $($_.Exception.Message)"
    }
    Add-Member -InputObject $report -MemberType NoteProperty -Name 'ModuleImportTest' -Value $moduleInfo

} catch {
    Add-Member -InputObject $report -MemberType NoteProperty -Name 'FATAL_ERROR' -Value "The harness script failed unexpectedly: $($_.Exception.Message)"
}

# --- Final Output ---
Write-Host "--- Harness Execution Complete. Returning JSON Report. ---"
Write-Host "--- Copy/paste the output below into jsononline.net/json-beautifier to view it nicely formatted. ---"
return $report | ConvertTo-Json -Depth 5