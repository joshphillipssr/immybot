#Requires -Version 5.1
<#
.SYNOPSIS
    Orchestrates the tiered, robust uninstallation of the SentinelOne agent from the Metascript context.
.DESCRIPTION
    This script is the definitive uninstaller for the C9SP-SentinelOne software package. It runs
    in the ImmyBot Metascript context and follows the "Context-Pure" architectural pattern.

    1. METASCRIPT: Retrieves credentials (Passphrase, SiteToken) from the $ScriptVariables hashtable.
    2. METASCRIPT: Fetches the C9S1EndpointTools.psm1 helper module from the script repository.
    3. SYSTEM: Uses Invoke-ImmyCommand to execute the tiered removal logic on the endpoint as SYSTEM.
       - The endpoint logic uses functions from the injected module for reliable presence checks.
       - It includes on-demand downloading of required installers and robust exit code validation.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    5.0.0 - Final Metascript Architecture
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# This section runs in the main ImmyBot script engine (Linux/PowerShell Core).
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

try {
    Write-Verbose "--- C9SP-S1 Uninstallation Metascript Started ---"

    # Step 1: Get credentials from the pre-populated $ScriptVariables hashtable.
    # This discovery from 07/08/25 is the key to making this work.
    Write-Verbose "Retrieving credentials from `$ScriptVariables..."
    $Passphrase = $ScriptVariables.Passphrase
    $SiteToken = $ScriptVariables.SiteToken # Required for Method 2
    
    if ([string]::IsNullOrWhiteSpace($Passphrase)) { throw "Passphrase was not found in `$ScriptVariables." }
    if ([string]::IsNullOrWhiteSpace($SiteToken)) { throw "SiteToken was not found in `$ScriptVariables." }
    Write-Verbose "Successfully retrieved credentials."

    # Step 2: Get our endpoint helper module content from the ImmyBot script repository.
    Write-Verbose "Loading C9S1EndpointTools.psm1 module content..."
    $moduleContent = (Get-ImmyScript -Name 'C9S1EndpointTools' -ErrorAction Stop).Content

    # Step 3: Invoke the uninstallation logic on the endpoint as SYSTEM.
    Write-Host "Invoking tiered removal logic on the endpoint..."
    $result = Invoke-ImmyCommand -ScriptBlock {
        # =========================================================================
        # --- SYSTEM CONTEXT SCRIPTBLOCK ---
        # This ENTIRE block runs on the endpoint as SYSTEM (Windows/PowerShell 5.1).
        # =========================================================================
        
        # Step 3a: Define the helper functions from our module.
        Invoke-Expression -Command $using:moduleContent
        
        # Step 3b: Receive credentials from the Metascript.
        $Passphrase = $using:Passphrase
        $SiteToken = $using:SiteToken

        # Helper function for on-demand downloads.
        function Ensure-InstallerAvailable {
            [CmdletBinding()]
            param(
                [string]$DownloadUrl,
                [string]$FileName
            )
            $destinationPath = Join-Path $env:TEMP $FileName
            try {
                Write-Verbose "Downloading installer from '$DownloadUrl' to '$destinationPath'..."
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $destinationPath -ErrorAction Stop
                Write-Verbose "Download complete."
                return $destinationPath
            }
            catch { throw "Failed to download the required installer '$FileName'. Error: $_" }
        }

        $downloadedInstallerPath = $null
        $legacyCleanerPath = $null

        try {
            # --- Tiered Removal Logic (using C9S1EndpointTools functions) ---

            # Method 1: S1 Recommended Uninstall (via uninstall.exe)
            Write-Verbose "--- Method 1: Attempting S1 Recommended Uninstall ---"
            if (Test-S1ServicePresence) {
                $installDir = Join-Path -Path ${env:ProgramFiles} -ChildPath 'SentinelOne\Sentinel Agent'
                $uninstallExe = Join-Path -Path $installDir -ChildPath "uninstall.exe"
                if (Test-Path -LiteralPath $uninstallExe) {
                    $argList = @('/uninstall', '/norestart', '/q', '/k', $Passphrase)
                    $process = Start-Process -FilePath $uninstallExe -ArgumentList $argList -Wait -PassThru -NoNewWindow
                    Write-Verbose "Method 1 finished with exit code: $($process.ExitCode)."
                    if ((Test-S1ServicePresence -eq $false) -and (Test-S1InstallPathPresence -eq $false)) {
                        Write-Host "SUCCESS: Method 1 was successful."
                        return $true
                    }
                } else { Write-Warning "Standard uninstaller not found. Skipping." }
            } else { Write-Warning "S1 service not present. Skipping." }
            Write-Warning "Method 1 failed or was skipped. Proceeding to Method 2."

            # Method 2: Modern Installer with Clean Flag
            Write-Verbose "--- Method 2: Attempting Modern Installer with '-c' flag ---"
            $installerUrl = "https://github.com/joshphillipssr/immybot/raw/refs/heads/main/SentinelOne/Tools/SentinelOneInstaller_windows_64bit_v24_2_3_471.exe"
            $downloadedInstallerPath = Ensure-InstallerAvailable -DownloadUrl $installerUrl -FileName "SentinelOneInstaller.exe"
            $argList = @('-c', '-k', $Passphrase, '-t', $SiteToken)
            $process = Start-Process -FilePath $downloadedInstallerPath -ArgumentList $argList -Wait -PassThru -NoNewWindow
            Write-Verbose "Method 2 finished with exit code: $($process.ExitCode)."
            if ((Test-S1ServicePresence -eq $false) -and (Test-S1InstallPathPresence -eq $false)) {
                Write-Host "SUCCESS: Method 2 was successful."
                return $true
            }
            Write-Warning "Method 2 failed. Proceeding to Method 3."

            # Method 3: Legacy Standalone Cleaner
            Write-Verbose "--- Method 3: Attempting Legacy Standalone Cleaner ---"
            $cleanerUrl = "https://github.com/joshphillipssr/immybot/raw/refs/heads/main/SentinelOne/Tools/SentinelCleaner_22_1GA_64.exe"
            $legacyCleanerPath = Ensure-InstallerAvailable -DownloadUrl $cleanerUrl -FileName "SentinelCleaner.exe"
            $process = Start-Process -FilePath $legacyCleanerPath -Wait -PassThru -NoNewWindow
            Write-Verbose "Method 3 finished with exit code: $($process.ExitCode)."
            if ((Test-S1ServicePresence -eq $false) -and (Test-S1InstallPathPresence -eq $false)) {
                Write-Host "SUCCESS: Method 3 was successful."
                return $true
            }

            # Final Failure within the scriptblock
            throw "ALL REMOVAL METHODS FAILED. The agent is still present on the machine."

        } catch {
            $endpointError = "A fatal error occurred on the endpoint: $_"
            Write-Error $endpointError
            throw $endpointError
        } finally {
            if ($downloadedInstallerPath -and (Test-Path $downloadedInstallerPath)) { Remove-Item -Path $downloadedInstallerPath -Force -ErrorAction SilentlyContinue }
            if ($legacyCleanerPath -and (Test-Path $legacyCleanerPath)) { Remove-Item -Path $legacyCleanerPath -Force -ErrorAction SilentlyContinue }
        }
    } # --- End of Invoke-ImmyCommand ---

    if ($result) {
        Write-Host "[SUCCESS] Uninstallation Metascript completed successfully."
    }

} catch {
    $errorMessage = "A fatal error occurred in the Uninstallation Metascript: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}