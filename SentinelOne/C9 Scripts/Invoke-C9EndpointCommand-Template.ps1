<#
.SYNOPSIS
    A template for executing and validating any command-line tool using the Invoke-C9EndpointCommand wrapper.

.DESCRIPTION
    This script provides a standardized, reusable pattern for running command-line executables on an endpoint via the ImmyBot Metascript context.
    It leverages the custom 'Invoke-C9EndpointCommand' function from the C9MetascriptHelpers module to ensure reliable execution and output capturing.

    The template demonstrates the complete workflow:
    1. Import the necessary helper module.
    2. Define the command, arguments, and a validation string.
    3. Execute the command using the wrapper function.
    4. Analyze the structured result object to check the exit code and validate the output.

.NOTES
    Author: Josh Phillips
    Date:   July 24, 2025

    How to use this template:
    -------------------------
    To adapt this template for a new command, modify the three variables in the TEMPLATE CONTEXT section:

    1. $filePath: 
       Set this to the name of the executable (e.g., "nslookup.exe", "ipconfig.exe") if it's in the system's PATH, 
       or provide the full, absolute path to the executable if it is not.

    2. $argumentList: 
       This is an array of strings. Each part of the command's arguments should be a separate element.
       Example for 'ping -n 4 google.com': $argumentList = "-n", "4", "google.com"

    3. $validation: 
       A simple string that you expect to find in the command's successful *Standard Output*. 
       This provides an extra layer of confirmation that the command did what you expected.
#>
# =================================================================================
# --- TEMPLATE CONTEXT ---
# =================================================================================
$filePath = "nslookup.exe"
$argumentList = @("www.google.com")
$validation = "Addresses:"
# =================================================================================
# --- TEMPLATE CONTEXT END ---
# =================================================================================

# --- Import the necessary helper module ---
try {
    Import-Module "C9MetascriptHelpers" -ErrorAction Stop
    Write-Host "Successfully imported C9MetascriptHelpers module."
} catch {
    throw "Failed to import C9MetascriptHelpers module. Ensure it is saved as a Global Script in ImmyBot."
}

# ---Execute the command using the robust wrapper ---
Write-Host "--- Executing $($filePath) $($argumentList -join ' ') ---"
$result = Invoke-C9EndpointCommand -FilePath $filePath -ArgumentList $argumentList

# --- Analyze the structured result from the wrapper ---
if ($result) {
    # Check 1: Was the exit code successful (usually 0)?
    if ($result.ExitCode -eq 0) {
        Write-Host "[SUCCESS] $($filePath) $($argumentList -join ' ') completed with Exit Code 0."
    } else {
        Write-Error "[FAILURE] $($filePath) $($argumentList -join ' ') returned a non-zero exit code: $($result.ExitCode)."
    }

    # Check 2: Did the standard output contain our expected validation text?
    if ($result.StandardOutput -match $validation) {
        Write-Host "[VALIDATION PASSED] The output contains the expected '$($validation)' line."
    } else {
        Write-Warning "[VALIDATION WARNING] The output did not contain the expected '$($validation)' text."
    }
} else {
    throw "[FATAL] Invoke-C9EndpointCommand did not return a result object. A script error likely occurred."
}