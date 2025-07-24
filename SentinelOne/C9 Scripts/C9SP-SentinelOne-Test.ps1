# Version: 20250721-01
#
# Testing Script for SentinelOne Software Package
#
# This script determines if the software is in a compliant state.
# It uses a "receipt file" system and includes a manual override for testing.
#
# Returns:
#   $true: If the s1_is_installed.txt receipt file exists AND the override is not present. (Workflow STOPS)
#   $false: If the s1_is_null.txt override file exists, OR if the receipt file is missing. (Workflow proceeds to UNINSTALL)

$VerbosePreference = 'Continue'

# --- FILE DEFINITIONS ---
# The standard "receipt" file, created by the Post-Install script.
$installedFlagFile = "C:\ProgramData\ImmyBot\S1\s1_is_installed.txt"
# The manual "override" file, used to force an uninstall for testing.
$forceNullFlagFile = "C:\ProgramData\ImmyBot\S1\s1_is_null.txt"


# --- LOGIC ---
Write-Verbose "--- S1 Test Script Started ---"

# 1. Check for the manual override file first. This takes precedence.
if (Test-Path -LiteralPath $forceNullFlagFile) {
    Write-Verbose "OVERRIDE DETECTED: Found '$forceNullFlagFile'."
    Write-Verbose "Forcing test to return \$false to trigger the UNINSTALL workflow."
    return $false
}

# 2. If no override is found, perform the standard check for the "receipt" file.
#    Test-Path is a built-in cmdlet that returns a boolean ($true or $false),
#    which is exactly what the ImmyBot testing script expects.
$isInstalled = Test-Path -Path $installedFlagFile

if ($isInstalled) {
    Write-Verbose "Receipt file '$installedFlagFile' found. Test returns \$true."
} else {
    Write-Verbose "Receipt file '$installedFlagFile' NOT found. Test returns \$false."
}

return $isInstalled
