<#
.SYNOPSIS
    Orchestrates the tiered, robust uninstallation of the SentinelOne agent from the Metascript context.
.DESCRIPTION
    This script is the definitive uninstaller for the C9SP-SentinelOne software package. It is
    designed to run in the software package's "Uninstall" script context.
.NOTES
    Author:     Josh Phillips
    Created:    07/15/2025
    Version:    20250721-02 - Fixed ConstrainedLanguage error by removing -PassThru and using $LASTEXITCODE.
#>

# =================================================================================
# --- METASCRIPT CONTEXT ---
# =================================================================================

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

try {
    Write-Verbose "--- C9-S1 Uninstall Metascript Started ---"

    $Passphrase = $null
    Write-Verbose "Attempting to retrieve passphrase from integration..."
    try {
        # This will get the agent-specific passphrase if the agent is known to the integration.
        $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($Passphrase)) { throw "Integration returned a null or empty passphrase." }
        Write-Verbose "Successfully retrieved passphrase via integration."
    } catch {
        Write-Warning "Could not retrieve uninstall passphrase. Error: $($_.Exception.Message). Proceeding without it, which will limit removal options."
    }

    Write-Host "Invoking self-contained removal logic on the endpoint..."
    $result = Invoke-ImmyCommand -ScriptBlock {
        # =========================================================================
        # --- SYSTEM CONTEXT SCRIPTBLOCK (Endpoint Logic) ---
        # =========================================================================

        $logDir = "C:\ProgramData\ImmyBot\S1"
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $logFile = Join-Path -Path $logDir -ChildPath "s1_uninstall_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Start-Transcript -Path $logFile -Force

        $Passphrase = $using:Passphrase
        $downloadedInstallerPath = $null
        $legacyCleanerPath = $null

        function Test-S1ServicePresence {
            return [boolean](Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue)
        }

        function Test-S1InstallPathPresence {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
            if(-not $service){ return $false }
            $installDir = Split-Path -Path ($service.PathName.Trim('"')) -Parent
            return Test-Path -Path $installDir
        }

        function Ensure-InstallerAvailable {
            [CmdletBinding()]
            param([string]$DownloadUrl, [string]$FileName)
            
            $immyTempPath = Join-Path -Path $env:ProgramData -ChildPath 'ImmyBot\Temp'
            if (-not (Test-Path -Path $immyTempPath)) {
                New-Item -Path $immyTempPath -ItemType Directory -Force | Out-Null
            }
            $destinationPath = Join-Path $immyTempPath $FileName
            
            if (Test-Path -Path $destinationPath) {
                Write-Verbose "File '$FileName' already exists at '$destinationPath'. Skipping download."
                return $destinationPath
            }

            try {
                Write-Verbose "Attempting to download from '$DownloadUrl' to path '$destinationPath'..."
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $destinationPath -UseBasicParsing -ErrorAction Stop
                Write-Host "SUCCESS: File downloaded to '$destinationPath'."
                return $destinationPath
            } catch { 
                throw "Failed to download '$FileName'. Error: $_" 
            }
        }
        
        try {
            if (-not [string]::IsNullOrWhiteSpace($Passphrase)) {
                # ======================= METHOD 1 =======================
                Write-Verbose "[M1.0] --- Method 1: Attempting S1 Recommended Uninstall (Requires Passphrase) ---"
                if (Test-S1ServicePresence) {
                    Write-Verbose "[M1.1] PASSED: The 'SentinelAgent' service was found."
                    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'"
                    $installDir = Split-Path -Path ($service.PathName.Trim('"')) -Parent
                    Write-Verbose "[M1.2] Found dynamic path: '$installDir'"
                    $uninstallExe = Join-Path -Path $installDir -ChildPath "uninstall.exe"
                    
                    if (Test-Path -LiteralPath $uninstallExe) {
                        Write-Verbose "[M1.3] PASSED: Standard uninstaller found. Executing..."
                        $argList = @('/uninstall', '/norestart', '/q', '/k', $Passphrase)
                        $uninstallOutput = & $uninstallExe $argList 2>&1
                        Write-Verbose "[M1.4] Process finished with exit code: $LASTEXITCODE."
                        if ($uninstallOutput) {
                            Write-Verbose "[M1.4] --- Begin Uninstaller Output ---"
                            $uninstallOutput | ForEach-Object { Write-Verbose $_ }
                            Write-Verbose "[M1.4] --- End Uninstaller Output ---"
                        }
                        if ( -not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence) ) {
                            Write-Host "[SUCCESS] Method 1 was successful. Agent is fully removed."
                            return $true
                        } else {
                            Write-Warning "[M1.5] FAILED: Verification failed after Method 1."
                        }
                    } else { Write-Warning "[M1.3] FAILED: Standard uninstaller not found at '$uninstallExe'." }
                } else { Write-Warning "[M1.1] SKIPPED: 'SentinelAgent' service not present." }
                Write-Warning "[END M1] Method 1 did not result in a successful removal. Proceeding..."

                # ======================= METHOD 2 =======================
                Write-Verbose "--- Method 2: Attempting Modern Installer with '-c' flag (Requires Passphrase) ---"
                $installerUrl = "https://raw.githubusercontent.com/joshphillipssr/immybot/main/SentinelOne/Tools/SentinelOneInstaller_windows_64bit_v24_2_3_471.exe"
                $downloadedInstallerPath = Ensure-InstallerAvailable -DownloadUrl $installerUrl -FileName "SentinelOneInstaller.exe"
                $argList = @('-c', '-k', $Passphrase, '--qn') # Added --qn as per our findings
                
                # CHANGED: Removed -PassThru, which returns a complex object that is not serializable.
                Start-Process -FilePath $downloadedInstallerPath -ArgumentList $argList -Wait -NoNewWindow
                # CHANGED: Use the built-in $LASTEXITCODE variable to get the result.
                Write-Verbose "Method 2 finished with exit code: $LASTEXITCODE."
                
                if ( -not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence) ) {
                    Write-Host "SUCCESS: Method 2 was successful."
                    return $true
                }
                Write-Warning "Method 2 failed. Proceeding..."
            } else {
                Write-Warning "SKIPPING Methods 1 & 2 because no uninstall passphrase was provided."
            }
            
            # ======================= METHOD 3 =======================
            Write-Verbose "--- Method 3: Attempting Legacy Standalone Cleaner ---"
            if ( -not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence) ) {
                Write-Host "[SUCCESS] Agent already appears to be removed before Method 3. Exiting."
                return $true
            }
            $cleanerUrl = "https://raw.githubusercontent.com/joshphillipssr/immybot/main/SentinelOne/Tools/SentinelCleaner_22_1GA_64.exe"
            $legacyCleanerPath = Ensure-InstallerAvailable -DownloadUrl $cleanerUrl -FileName "SentinelCleaner.exe"
            
            # CHANGED: Removed -PassThru, which returns a complex object that is not serializable.
            Start-Process -FilePath $legacyCleanerPath -Wait -NoNewWindow
            # CHANGED: Use the built-in $LASTEXITCODE variable to get the result.
            Write-Verbose "Method 3 finished with exit code: $LASTEXITCODE."

            # Adding a small sleep to allow filesystem changes to settle after the cleaner runs.
            Start-Sleep -Seconds 5

            if ( -not (Test-S1ServicePresence) -and -not (Test-S1InstallPathPresence) ) {
                Write-Host "SUCCESS: Method 3 was successful."
                return $true
            }

            throw "ALL REMOVAL METHODS FAILED. The agent is still present on the machine."

        } catch {
            throw "A fatal error occurred on the endpoint: $_"
        } finally {
            Stop-Transcript
            if ($downloadedInstallerPath -and (Test-Path $downloadedInstallerPath)) { Remove-Item -Path $downloadedInstallerPath -Force -ErrorAction SilentlyContinue }
            if ($legacyCleanerPath -and (Test-Path $legacyCleanerPath)) { Remove-Item -Path $legacyCleanerPath -Force -ErrorAction SilentlyContinue }
        }
    }

    if ($result) {
        Write-Host "[SUCCESS] Uninstallation Metascript completed successfully."
    }

} catch {
    $errorMessage = "A fatal error occurred in the Uninstallation Metascript: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}
