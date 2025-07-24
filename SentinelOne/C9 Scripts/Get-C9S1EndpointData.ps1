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

try {
    # The #Requires statement above handles the import of our custom module.
    # We can use Write-Host for high-level status messages that are always visible in ImmyBot logs.
    Write-Host "Executing SentinelOne Health 'Get' script."
    Write-Host "This script gathers raw data for inventory or for a 'Test' script to evaluate."

    # Call the master function from our module. It handles all its own detailed logging.
    # The output of this function is the final return value of this script.
    $healthReport = Get-C9S1LocalHealthReport

    Write-Host "Successfully generated health report. Returning data object."
    
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