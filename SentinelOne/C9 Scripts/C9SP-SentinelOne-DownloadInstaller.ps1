<#
.SYNOPSIS
    Downloads the SentinelOne installer using the C9DIS-SentinelOne integration and the platform's native Download-File cmdlet.
.DESCRIPTION
    This script runs in the Metascript context. It leverages the C9DIS-SentinelOne integration
    to retrieve an authentication header, then passes that header along with the platform-provided
    URL to the built-in 'Download-File' function to perform a secure, authenticated download.
.NOTES
    Author:     Josh Phillips
    Created:    07/22/2025
    Version:    20250722-01
#>

# This entire script runs in the Metascript context.
# We wrap the logic in a try/catch block for robust error handling.
try {
    Write-Host "--- Download Process ---"

    # Step 1: Import our custom module to gain access to our helper functions.
    Write-Host "Importing C9SentinelOne module..."
    Import-Module C9SentinelOne -ErrorAction Stop

    # Step 2: Get the authentication header from our integration.
    # This call to our new, lightweight helper function replaces the manual API connection from the default scripts.
    Write-Host "Retrieving auth header from the C9DIS-SentinelOne integration..."
    $AuthHeader = Get-C9S1AuthHeader -ErrorAction Stop

    # Step 3: Call the built-in ImmyBot Download-File function.
    # The $URL and $InstallerFile variables are automatically populated by the platform at this stage
    # with the data from the DynamicVersion object that was created by our integration.
    Write-Host "Passing authenticated download request to the ImmyBot platform..."
    Write-Host "Source URL: $URL"
    Write-Host "Destination Path: $InstallerFile"

    # This is the call to the platform's own powerful download engine.
    Download-File -Source $URL -Destination $InstallerFile -Headers $AuthHeader -ErrorAction Stop

    Write-Host "[SUCCESS] Download-File cmdlet completed successfully."
    Write-Host "Installer has been downloaded to '$InstallerFile'."
    Write-Host "Download process done. Let's move on..."
}
catch {
    # If any step fails, this block will catch the error and report it clearly.
    # Casting $_ to a string is the ConstrainedLanguage-safe way to get the full error message.
    $errorMessage = "FATAL: The DownloadInstaller script failed. Error: $([string]$_)"
    Write-Error $errorMessage
    throw $errorMessage
}