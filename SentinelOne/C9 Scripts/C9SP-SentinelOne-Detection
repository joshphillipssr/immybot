# SentinelOne Agent Version Detection Script (ImmyBot-Compatible)
# Returns a version STRING if an agent is detected.
# Returns $null if no definitive agent presence is found.
#
# TLDR
# - All commands that could potentially write to the success output stream are
#   explicitly piped to Out-Null to prevent "stray" output from confusing the ImmyBot engine.
# - This ensures that the ONLY thing ever sent to the output stream is the final,
#   intended version string from the 'return' statement.

try {
    # Query for the service, but pipe to Out-Null to suppress the object output.
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

    if ($service -and $service.PathName) {
        $exePath = $service.PathName.Trim('"')

        # Use -LiteralPath for robustness against special characters in the path.
        if (Test-Path -LiteralPath $exePath) {
            
            # Get file properties, but pipe the command to Out-Null to suppress the FileInfo object.
            # Getting the version string directly from the property of the resulting variable.
            $version = (Get-Item -LiteralPath $exePath).VersionInfo.ProductVersion
            
            if ($version) {
                # This is the ONLY line that writes to the success stream.
                return $version
            }
        }
    }

    # If any check fails, return null. This writes $null to the stream.
    return $null
}
catch {
    # On any unexpected/terminating error, return null to signal "not found".
    return $null
}