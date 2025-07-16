#Requires -Version 5.1
<#
.SYNOPSIS
    Get-C9S1Health - The 'Get' script for the SentinelOne Health task.
.DESCRIPTION
    This Metascript orchestrates a health check on the remote endpoint. It runs within a Task
    Script context, which does not have an automatic module path. Therefore, it uses the
    ImmyBot-native function 'Get-ImmyScript' to retrieve the C9S1EndpointTools.psm1 module
    content. It then injects those function definitions into an Invoke-ImmyCommand script block,
    ensuring they are defined and executed in the correct System context on the endpoint.
.OUTPUTS
    [PSCustomObject] A detailed object containing the S1 agent's local health status.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    5.0.0
#>

param()

try {
    Write-Host "Executing Metascript: Get-C9S1Health Task"

    # Step 1: Use the ImmyBot-native function to get our module content. This is the required
    # method for loading a script/module within the Task Script Metascript context.
    $moduleScript = Get-ImmyScript -Name 'C9S1EndpointTools' -ErrorAction Stop
    $moduleContent = $moduleScript.Content
    Write-Host "Successfully loaded function definitions from ImmyBot script repository for 'C9S1EndpointTools'."

    # Step 2: Send the functions AND the command to the endpoint for remote execution.
    Write-Host "Invoking command on endpoint to generate the health report..."
    $result = Invoke-ImmyCommand -ScriptBlock {
        # This ENTIRE block runs on the endpoint as SYSTEM.

        # Step 2a: Define the functions. The `$using:moduleContent` statement injects the
        # raw text of our .psm1 file here. We use Invoke-Expression to execute that text,
        # which loads all the functions into the current (endpoint) session.
        Invoke-Expression -Command $using:moduleContent

        # Step 2b: Now that the functions are defined locally, we can call them.
        try {
            # We call our master function with -Verbose to ensure its detailed logging is captured.
            $report = Get-C9S1LocalHealthReport -Verbose
            
            # This return statement sends the $report object back to the Metascript.
            return $report
        }
        catch {
            # If the endpoint script fails, throw an error that the Metascript can see.
            $endpointError = "A fatal error occurred on the endpoint while generating the health report: $($_.Exception.Message)"
            Write-Error $endpointError
            throw $endpointError
        }
    }

    Write-Host "Successfully received health report from endpoint. Script complete."
    # The final object returned from Invoke-ImmyCommand becomes the output of this script.
    return $result
}
catch {
    # This catches errors from the Metascript itself (e.g., Get-ImmyScript failure)
    # or errors thrown from within the Invoke-ImmyCommand block.
    $errorMessage = "A fatal error occurred in the Get-C9S1Health Metascript: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}