# S1 Agent "Nuclear" Uninstallation Script (Immy Maintenance Task)
#
# PURPOSE:
# This script is designed to run as an ImmyBot "Reinstallation" or "Uninstallation" task.
# It is triggered when the "Test & Remediate" script fails, indicating a severely corrupted agent.
#
# WORKFLOW (based on research from ticket T20250611.0014, entry 06/25/2025):
# The script will attempt a tiered, sequential removal process, escalating in aggression:
# 1. Method 1: S1 Recommended standard uninstaller (uninstall.exe).
# 2. Method 2: Modern Installer with Clean flag (-c).
# 3. Method 3: Legacy Standalone Cleaner (SentinelCleaner.exe).
# After each attempt, it verifies success. If all methods fail, it throws a fatal error.

# --- SCRIPT PARAMETERS (Provided by ImmyBot) ---
# $InstallerFile: The full path to the primary (modern) SentinelOneInstaller.exe.
# $Passphrase: The agent removal passphrase.
# $SiteToken: The site-specific token for the agent.

$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

try {
    # --- Pre-flight Checks: Validate Required Variables ---
    Write-Verbose "--- S1 Nuclear Uninstallation Script Started ---"
    if ([string]::IsNullOrWhiteSpace($InstallerFile) -or -not (Test-Path -LiteralPath $InstallerFile)) {
        throw "InstallerFile variable was not provided by ImmyBot or the path is invalid. This is required for Methods 2 & 3."
    }
    if ([string]::IsNullOrWhiteSpace($Passphrase)) {
        throw "Passphrase variable was not provided by the ImmyBot environment. This is required for Method 2."
    }
    if ([string]::IsNullOrWhiteSpace($SiteToken)) {
        throw "SiteToken variable was not provided by the ImmyBot environment. This is required for Method 2."
    }
    Write-Verbose "All required variables (InstallerFile, Passphrase, SiteToken) have been provided."

    # --- Helper Functions ---
    function Get-S1InstallPath {
        $service = Get-Service -Name "SentinelAgent" -ErrorAction SilentlyContinue
        if ($service) {
            $exePath = (Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'").PathName.Replace('"', '')
            return Split-Path -Path $exePath -Parent
        }
        return $null
    }

    function Test-S1AgentRemoved {
        $serviceExists = Get-Service -Name "SentinelAgent" -ErrorAction SilentlyContinue
        $programDir = "C:\Program Files\SentinelOne"
        $dirExists = Test-Path -Path $programDir
        if (-not $serviceExists -and -not $dirExists) {
            Write-Verbose "VERIFICATION: SentinelAgent service and Program Files directory are gone."
            return $true
        }
        Write-Warning "VERIFICATION: SentinelOne artifacts still detected (Service: $($null -ne $serviceExists), Directory: $dirExists)."
        return $false
    }

    # --- Tiered Removal Logic ---

    # Method 1: S1 Recommended Uninstall (as documented 06/25/2025)
    Write-Verbose "--- Method 1: Attempting S1 Recommended Uninstall ---"
    $installPath = Get-S1InstallPath
    if ($installPath) {
        $uninstallExe = Join-Path -Path $installPath -ChildPath "uninstall.exe"
        if (Test-Path -LiteralPath $uninstallExe) {
            Write-Verbose "Found standard uninstaller at '$uninstallExe'."
            $args = "/uninstall /norestart /q /k `"$Passphrase`""
            Write-Verbose "Executing: `"$uninstallExe`" $args"
            $process = Start-Process -FilePath $uninstallExe -ArgumentList $args -Wait -PassThru -NoNewWindow
            Write-Verbose "Method 1 process finished with exit code $($process.ExitCode)."
            Start-Sleep -Seconds 10
            if (Test-S1AgentRemoved) {
                Write-Host "SUCCESS: Method 1 (Standard Uninstall) was successful."
                return $true
            }
        } else {
            Write-Warning "Standard uninstaller not found. Skipping Method 1."
        }
    } else {
        Write-Warning "S1 installation path not found. Skipping Method 1."
    }
    Write-Warning "Method 1 failed or was skipped. Proceeding to Method 2."

    # Method 2: Modern Installer with Clean Flag (as documented 06/25/2025 for 'ghost state')
    Write-Verbose "--- Method 2: Attempting Modern Installer with '-c' flag ---"
    $cleanerArgs = "-c -k `"$Passphrase`" -t `"$SiteToken`""
    Write-Verbose "Executing: `"$InstallerFile`" $cleanerArgs"
    $process = Start-Process -FilePath $InstallerFile -ArgumentList $cleanerArgs -Wait -PassThru -NoNewWindow
    Write-Verbose "Method 2 process finished with exit code $($process.ExitCode)."
    Start-Sleep -Seconds 10
    if (Test-S1AgentRemoved) {
        Write-Host "SUCCESS: Method 2 (Modern Installer Clean) was successful."
        return $true
    }
    Write-Warning "Method 2 failed. Proceeding to Method 3 (Nuclear Option)."

    # Method 3: Legacy Standalone Cleaner (as documented 06/25/2025 for severe corruption)
    Write-Verbose "--- Method 3 (Nuclear): Attempting Legacy Standalone Cleaner ---"
    $installerDir = Split-Path -Path $InstallerFile -Parent
    # Assumes the legacy cleaner is named this and is in the same folder as the modern installer.
    $legacyCleaner = Join-Path -Path $installerDir -ChildPath "SentinelCleaner_22_1GA_64.exe" 
    
    if (Test-Path -LiteralPath $legacyCleaner) {
        Write-Verbose "Found legacy cleaner at '$legacyCleaner'. Executing with no flags as per research."
        $process = Start-Process -FilePath $legacyCleaner -Wait -PassThru -NoNewWindow
        Write-Verbose "Method 3 process finished with exit code $($process.ExitCode)."
        # The legacy cleaner can be aggressive and may require a moment for services to be de-registered.
        Start-Sleep -Seconds 15
        if (Test-S1AgentRemoved) {
            Write-Host "SUCCESS: Method 3 (Legacy Cleaner) was successful."
            return $true
        }
    } else {
        Write-Warning "Legacy cleaner '$legacyCleaner' not found. Skipping Method 3."
    }

    # Final Failure
    throw "ALL REMOVAL METHODS FAILED. The SentinelOne agent is still present on the machine after exhausting all three automated removal methods. Manual intervention is required."

} catch {
    Write-Error "A fatal error occurred during the uninstallation process: $_"
    # Re-throw the error to ensure ImmyBot registers this script as a complete failure.
    throw
}