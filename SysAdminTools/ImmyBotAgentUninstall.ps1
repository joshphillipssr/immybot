<#
.SYNOPSIS
    A self-contained script to perform a complete and forceful uninstallation of the ImmyBot Agent.
.DESCRIPTION
    This script is designed to be executed from a secondary RMM (like NinjaRMM) with SYSTEM privileges.
    It systematically stops and disables ImmyBot services, terminates any lingering processes,
    attempts to run the native uninstaller, and performs a manual cleanup of all known file system
    and registry locations to ensure no remnants are left behind.
.NOTES
    - DO NOT run this script from an ImmyBot task. It will fail.
    - This script must be run as NT AUTHORITY\SYSTEM for full access.
    - This is a destructive, one-way operation.
#>

# --- Configuration ---
# Write all output to a log file for post-mortem analysis.
$logFile = "C:\IT\Scripts\Logs\C9_ImmyBot_Uninstall.log"
Start-Transcript -Path $logFile -Force

# --- Start of Execution ---
Write-Host "============================================================"
Write-Host "Starting ImmyBot Agent Forceful Uninstall at $(Get-Date)"
Write-Host "============================================================"

try {
    # --- Phase 1: Service and Process Neutralization ---
    Write-Host "[PHASE 1] Stopping and disabling ImmyBot services..."

    # Define the known service names. These are the most likely candidates.
    $serviceNames = @(
        "ImmyBot Agent",
        "ImmyBot Watchdog"
    )

    foreach ($serviceName in $serviceNames) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "--> Found service: '$($service.Name)'."
            try {
                # Ensure the service cannot restart itself.
                Write-Host "    - Setting startup type to 'Disabled'..."
                Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop

                # Stop the service if it is running.
                if ($service.Status -eq 'Running') {
                    Write-Host "    - Stopping service..."
                    Stop-Service -Name $service.Name -Force -ErrorAction Stop
                    Write-Host "    - Service stopped."
                } else {
                    Write-Host "    - Service is already stopped."
                }
            } catch {
                Write-Warning "    - An error occurred while managing service '$($service.Name)': $($_.Exception.Message)"
            }
        } else {
            Write-Host "--> Service '$serviceName' not found. Skipping."
        }
    }

    # Give services a moment to fully terminate.
    Start-Sleep -Seconds 5

    # Final "kill switch" for any processes that may have lingered or restarted.
    $processesToKill = Get-Process -Name "ImmyBot*" -ErrorAction SilentlyContinue
    if ($processesToKill) {
        Write-Host "--> Terminating lingering ImmyBot processes..."
        $processesToKill | ForEach-Object {
            Write-Host "    - Killing process: $($_.Name) (PID: $($_.Id))"
            Stop-Process -Id $_.Id -Force
        }
    } else {
        Write-Host "--> No lingering ImmyBot processes found."
    }
    Write-Host "[PHASE 1] Complete."


    # --- Phase 2: Execute Native Uninstaller (Best Effort) ---
    Write-Host "[PHASE 2] Attempting to run the native uninstaller (best effort)..."
    
    # Inno Setup uninstallers are commonly named this.
    $uninstallerPath = "C:\Program Files (x86)\ImmyBot\unins000.exe"

    if (Test-Path $uninstallerPath) {
        Write-Host "--> Found native uninstaller at '$uninstallerPath'."
        Write-Host "--> Executing with /VERYSILENT flags..."
        # Use standard Inno Setup silent switches. -Wait ensures we let it finish.
        Start-Process -FilePath $uninstallerPath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
        Write-Host "--> Native uninstaller execution finished."
    } else {
        Write-Warning "--> Native uninstaller not found. This is expected on a broken installation. Proceeding with manual cleanup."
    }
    Write-Host "[PHASE 2] Complete."


    # --- Phase 3: Aggressive File and Registry Cleanup ---
    Write-Host "[PHASE 3] Performing aggressive cleanup of all known ImmyBot locations..."

    $locationsToRemove = @(
        # Main program folder
        "C:\Program Files (x86)\ImmyBot",
        # Data and log folder
        "C:\ProgramData\ImmyBot",
        # Registry key for configuration
        "HKLM:\SOFTWARE\ImmyBot",
        # Registry key for 32-bit apps on 64-bit OS
        "HKLM:\SOFTWARE\WOW6432Node\ImmyBot"
    )

    foreach ($location in $locationsToRemove) {
        if (Test-Path $location) {
            Write-Host "--> Removing location: '$location'..."
            try {
                # -Recurse and -Force are essential for complete removal.
                Remove-Item -Path $location -Recurse -Force -ErrorAction Stop
                Write-Host "    - Successfully removed."
            } catch {
                Write-Warning "    - An error occurred removing '$location': $($_.Exception.Message)"
            }
        } else {
            Write-Host "--> Location not found, skipping: '$location'"
        }
    }
    Write-Host "[PHASE 3] Complete."

} catch {
    Write-Error "A fatal, unexpected error occurred during the uninstallation process."
    Write-Error $_.Exception.ToString()
} finally {
    Write-Host "============================================================"
    Write-Host "ImmyBot Agent uninstallation script finished at $(Get-Date)"
    Write-Host "Review the log file at '$logFile' for details."
    Write-Host "============================================================"
    Stop-Transcript
}
