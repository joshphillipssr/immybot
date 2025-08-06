# Metascript Documentation Generator - v10 (Correct Context)
#
# PURPOSE:
# This is a METASCRIPT that uses Invoke-ImmyCommand to execute the
# documentation generator on the endpoint in the SYSTEM context.
# This correctly separates the "orchestrator" from the "executor".

# --- METASCRIPT: PREPARATION ---
$VerbosePreference = 'Continue'
Write-Output "METASCRIPT: Preparing to generate documentation on the endpoint."

# Define the output file path here in the Metascript.
# We will pass this down to the System context using the '$using:' scope modifier.
$outputFile = "C:\ProgramData\ImmyBot\Metascript_Command_Reference.txt"

Write-Output "METASCRIPT: The final file will be saved to '$outputFile' on the target machine."
Write-Output "METASCRIPT: This may take a minute or two to run. Please be patient."


# --- METASCRIPT: EXECUTING THE COMMAND ON THE ENDPOINT ---
Invoke-ImmyCommand -ScriptBlock {
    # >>>>> EVERYTHING INSIDE THIS BLOCK RUNS ON THE ENDPOINT AS THE SYSTEM ACCOUNT <<<<<

    # Initialize the file on the endpoint using the path passed down from the Metascript.
    Set-Content -Path $using:outputFile -Value "ImmyBot Metascript Command Reference - Generated on $(Get-Date)"

    # Get all available commands.
    $commands = Get-Command -CommandType Function, Cmdlet | Sort-Object -Property Name
    Add-Content -Path $using:outputFile -Value "`nFound $($commands.Count) commands to document.`n"

    # Loop through each command and build its documentation.
    foreach ($cmd in $commands) {
        # Start building the string for this specific command.
        $commandDoc = "## $($cmd.Name)`n`n"

        try {
            # TIER 1: ATTEMPT TO GET RICH HELP
            $helpInfo = Get-Help $cmd.Name -Full -ErrorAction Stop
            $commandDoc += "SYNOPSIS:`n$($helpInfo.Synopsis)`n`n"
            $commandDoc += "DESCRIPTION:`n$($helpInfo.Description.Text)`n`n"
            if ($helpInfo.Parameters.Parameter.Count -gt 0) {
                $commandDoc += "PARAMETERS:`n"
                foreach ($param in $helpInfo.Parameters.Parameter) {
                    $commandDoc += "- $($param.Name) <$($param.Type.Name)> (Required: $($param.Required))`n"
                }
            }
        }
        catch {
            # TIER 2: FALLBACK TO BASIC DEFINITION
            try {
                $commandDoc += "SYNTAX DEFINITION:`n"
                $commandDoc += (Get-Command $cmd.Name).Definition
            }
            catch {
                # TIER 3: FINAL FALLBACK
                $commandDoc += "Could not retrieve any help or syntax information for this command."
            }
        }

        # Append this command's completed documentation to the master file.
        Add-Content -Path $using:outputFile -Value "`n$commandDoc`n"
    }

    Add-Content -Path $using:outputFile -Value "`n--- SCRIPT FINISHED ---"
    
    # >>>>> END OF THE SCRIPT BLOCK RUNNING ON THE ENDPOINT <<<<<
}

# --- METASCRIPT: CONFIRMATION ---
# This runs after Invoke-ImmyCommand is finished.
Write-Output "METASCRIPT: SUCCESS! The generation task has completed."
Write-Output "METASCRIPT: You can now browse to the endpoint's File Explorer in ImmyBot and download the file:"
Write-Output $outputFile