# =================================================================================
# Name:     C9SP-SentinelOne-PostInstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

# Post-Install Script for ImmyBot
#
# This script creates a flag file to signify that the "installation"
# process has completed successfully.

$flagFile = "C:\ProgramData\ImmyBot\S1\s1_is_installed.txt"

# The New-Item cmdlet creates the file.
# -ItemType File specifies we are creating a file, not a directory.
# -Force is crucial: it will automatically create the parent directories
# (C:\ProgramData\ImmyBot\S1) if they do not already exist.
#
# We pipe the output to Out-Null to prevent PowerShell from printing
# information about the new file to the console, keeping logs clean.
New-Item -Path $flagFile -ItemType File -Force | Out-Null

Write-Host "Successfully created the flag file at $flagFile"