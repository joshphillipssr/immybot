#Requires -Version 5.1
<#
.SYNOPSIS
    Orchestrates the tiered, robust uninstallation of the SentinelOne agent from the Metascript context.
.DESCRIPTION
    This script is the definitive uninstaller for the C9SP-SentinelOne software package. It is
    designed to run in the software package's "Uninstall" script context.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    9.1.0 - Syntax and Logic Cleanup
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

try {
    Write-Verbose "--- C9-S1 Uninstall Metascript Started ---"

    # Step 1: Manually invoke the integration capability to get the agent's passphrase.
    Write-Verbose "Calling Get-IntegrationAgentUninstallToken to retrieve passphrase..."
    $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($Passphrase)) { throw "Get-IntegrationAgentUninstallToken did not return a passphrase." }
    Write-Verbose "Successfully retrieved passphrase via integration."

    # Step 2: Invoke the uninstallation logic on the endpoint as SYSTEM.
    Write-Host "Invoking self-contained removal logic on the endpoint..."
    $result = Invoke-ImmyCommand -ScriptBlock {
        
        $Passphrase = $using:Passphrase
        
        # ===================== INLINED HELPER FUNCTIONS (Corrected) ====================
        
        function Test-S1ServicePresence {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
            return [boolean]$service.
        }

        function Test-S1InstallPathPresence {
            $installPath = Join-Path -Path $env:ProgramFiles -ChildPath 'SentinelOne\Sentinel Agent'
            return Test-Path -Path $installPath
        }

        function Ensure-InstallerAvailable {
            [CmdletBinding()]
            param([string]$DownloadUrl, [string]$FileName)
            $destinationPath = Join-Path $env:TEMP $FileName
            try {
                Write-Verbose "Downloading from '$DownloadUrl' to '$destinationPath'..."
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $destinationPath -ErrorAction Stop
                return $destinationPath
            } catch { throw "Failed to download '$FileName'. Error: $_" }
        }

        # ==============================================================================

        $downloadedInstallerPath = $null
        $legacyCleanerPath = $null

        try {
            # --- Tiered Removal Logic (Complete and Corrected) ---

            # Method 1: S1 Recommended Uninstall
            Write-Verbose "--- Method 1: Attempting S1 Recommended Uninstall ---"
            if (Test-S1ServicePresence) {
                $installDir = Join-Path -Path ${env:ProgramFiles} -ChildPath 'SentinelOne\Sentinel Agent'
                $uninstallExe = Join-Path -Path $installDir -ChildPath "uninstall.exe"
                if (Test-Path -LiteralPath $uninstallExe) {
                    $argList = @('/uninstall', '/norestart', '/q', '/k', $Passphrase)
                    $process = Start-Process -FilePath $uninstallExe -ArgumentList $argList -Wait -PassThru -NoNewWindow
                    Write-Verbose "Method 1 finished with exit code: $($process.ExitCode)."
                    if (-not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence)) {
                        Write-Host "SUCCESS: Method 1 was successful."
                        return $true
                    }
                } else { Write-Warning "Standard uninstaller not found. Skipping."}
            } else { Write-Warning "S1 service not present. Skipping." }
            Write-Warning "Method 1 failed or was skipped. Proceeding to Method 2."

            # FIX: Restoring the logic for Methods 2 and 3.
            
            # Method 2: Modern Installer with Clean Flag
            Write-Verbose "--- Method 2: Attempting Modern Installer with '-c' flag ---"
            $installerUrl = "https://github.com/joshphillipssr/immybot/raw/refs/heads/main/SentinelOne/Tools/SentinelOneInstaller_windows_64bit_v24_2_3_471.exe"
            $downloadedInstallerPath = Ensure-InstallerAvailable -DownloadUrl $installerUrl -FileName "SentinelOneInstaller.exe"
            # NOTE: SiteToken is not used as per your previous note. If needed, it must be passed from the Metascript.
            $argList = @('-c', '-k', $Passphrase) 
            $process = Start-Process -FilePath $downloadedInstallerPath -ArgumentList $argList -Wait -PassThru -NoNewWindow
            Write-Verbose "Method 2 finished with exit code: $($process.ExitCode)."
            if (-not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence)) {
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
            if (-not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence)) {
                Write-Host "SUCCESS: Method 3 was successful."
                return $true
            }
            
            # FIX: Removing the stray diagnostic code block that was here.

            throw "ALL REMOVAL METHODS FAILED. The agent is still present on the machine."

        } catch {
            throw "A fatal error occurred on the endpoint: $_"
        } finally {
            if ($downloadedInstallerPath -and (Test-Path $downloadedInstallerPath)) { Remove-Item -Path $downloadedInstallerPath -Force -ErrorAction SilentlyContinue }
            if ($legacyCleanerPath -and (Test-Path $legacyCleanerPath)) { Remove-Item -Path $legacyCleanerPath -Force -ErrorAction SilentlyContinue }
        }
    } # --- End of Invoke-ImmyCommand ScriptBlock ---

    if ($result) {
        Write-Host "[SUCCESS] Uninstallation Metascript completed successfully."
    }

} catch {
    $errorMessage = "A fatal error occurred in the Uninstallation Metascript: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}