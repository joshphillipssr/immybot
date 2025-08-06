# =================================================================================
# Name:     C9SP-SentinelOne-Detection Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

# $VerbosePreference = 'Continue'
$flagFile = "C:\ProgramData\ImmyBot\S1\s1_is_installed.txt"

Write-Host "[$using:ScriptName] Detection & Flagging Script Started..."

try {

    Write-Host "[$using:ScriptName] [Step 1] Checking for SentinelOne installation directory..."
    $s1ProgramFilesPath = Resolve-Path -Path "C:\Program Files\Sentinel*" -ErrorAction SilentlyContinue

    if (-not $s1ProgramFilesPath) {
        Write-Host "[$using:ScriptName] [Step 1] No Sentinel* installation directory found."
        Remove-Item -Path $flagFile -Force -ErrorAction SilentlyContinue
        return $null
    }

    Write-Host "[$using:ScriptName] [Step 1] Found installation directory."
    # Don't really need this anymore
    Write-Host "[$using:ScriptName] [Step 2] Creating a presence flag file."
    New-Item -Path (Split-Path $flagFile -Parent) -ItemType Directory -Force | Out-Null
    New-Item -Path $flagFile -ItemType File -Force | Out-Null

    Write-Host "[$using:ScriptName] [Step 3] Querying for a specific version..."
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

    if ($service -and $service.PathName) {
        $exePath = $service.PathName.Trim('"')
        if (Test-Path -LiteralPath $exePath) {
            $fileInfo = Get-Item -LiteralPath $exePath -ErrorAction SilentlyContinue
            $version = $fileInfo.VersionInfo.ProductVersion
            
            if ($version) {
                Write-Host "[$using:ScriptName] [Step 3] Found SentinelOne version: '$version'."
                return $version
            }
        }
    }

    # In order to resolve the broken install scenarios, we need to go to the Test phase.
    # The only way to do that is to pass the detection phase. So we will report a version
    # if there is any trace of SentinelOne installed.
    $hardcodedVersion = "24.2.3.471"
    
    Write-Host "[$using:ScriptName] [Step 3] Directory exists, but could not determine a specific version."
    Write-Host "[$using:ScriptName] This indicates a broken agent. Returning hardcoded version '$hardcodedVersion' to trigger the Test phase."
    return $hardcodedVersion 
}
catch {
    Write-Host "[$using:ScriptName] S1 Detection Script FAILED due to an unexpected error: $($_.Exception.Message)"
    Remove-Item -Path $flagFile -Force -ErrorAction SilentlyContinue
    return $null
}