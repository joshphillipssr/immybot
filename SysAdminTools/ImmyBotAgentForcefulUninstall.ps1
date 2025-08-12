# =================================================================================
# Name:     Surgical-Remove-CorruptMSI.ps1
# Purpose:  Forcefully removes a specific MSI registration and its associated files
#           to break the Windows Installer self-repair loop.
# Author:   Josh Phillips
# Date:     08/11/2025
# =================================================================================

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# --- Configuration: The data we gathered from our successful diagnostic script ---
$targetProductCode = "{67F85C1E-29B2-45A6-ABC4-6E198888AEEC}"
$targetProductName = "ImmyBot Agent"
$targetServiceName = "ImmyBot Agent"
$targetProcessName = "ImmyBot.Agent"
$targetInstallDir  = "C:\Program Files (x86)\ImmyBot"

Write-Host -ForegroundColor Cyan "--- Starting Surgical Removal of '$targetProductName' ---"

# --- Phase 1: Terminate all running processes and services ---
try {
    Write-Host "Phase 1: Terminating agent services and processes..."
    $service = Get-Service -Name $targetServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Stopping service: $($service.Name)..."
        Stop-Service -InputObject $service -Force
    }

    $process = Get-Process -Name $targetProcessName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "Stopping process: $($process.Name)..."
        Stop-Process -InputObject $process -Force
    }
    Write-Host -ForegroundColor Green "[SUCCESS] All processes and services terminated."
} catch {
    Write-Warning "An error occurred during termination, which may be expected if services/processes were already stopped. Error: $($_.Exception.Message)"
}

# --- Phase 2: Surgically remove registry keys ---
try {
    Write-Host "`nPhase 2: Removing Windows Installer registry registrations..."
    
    # This is the standard Uninstall key.
    $uninstallKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$targetProductCode"
    
    # This is the "packed" GUID key that Win32_Product uses. We must build this path manually.
    function Convert-GuidToPackedGuid {
        param([string]$Guid)
        $guidParts = $Guid.Trim('{}').Split('-')
        # Reverse bytes for first three parts
        $packed = ""
        $packed += -join (($guidParts[0] -split '(.{2})' | Where-Object {$_})[-1..0])
        $bytes1 = $guidParts[1] -split '(.{2})' | Where-Object {$_}
        $packed += -join (($guidParts[2] -split '(.{2})' | Where-Object {$_})[(-1)..0])
        $packed += -join $bytes1
        $packed += -join (($guidParts[2] -split '(.{2})' | Where-Object {$_})[-1..0])
        # For the last two parts, swap each pair of characters
        foreach ($part in $guidParts[3,4]) {
            for ($i = 0; $i -lt $part.Length; $i += 2) {
                $packed += $part.Substring($i,2)
            }
        }
        return $packed.ToUpper()
    }
    $packedGuid = Convert-GuidToPackedGuid -Guid $targetProductCode
    if (-not $packedGuid -or $packedGuid.Length -ne 32) {
        Write-Error "Failed to convert ProductCode to packed GUID. Aborting registry removal."
        exit 1
    }
    $installerProductKeyPath = "HKLM:\SOFTWARE\Classes\Installer\Products\$packedGuid"

    # Remove the keys
    if (Test-Path $uninstallKeyPath) {
        Write-Host "Removing Uninstall key: $uninstallKeyPath"
        Remove-Item -Path $uninstallKeyPath -Recurse -Force
    }
    if (Test-Path $installerProductKeyPath) {
        Write-Host "Removing Installer Product key: $installerProductKeyPath"
        Remove-Item -Path $installerProductKeyPath -Recurse -Force
    }
    
    Write-Host -ForegroundColor Green "[SUCCESS] Registry keys removed."
} catch {
    Write-Error "A fatal error occurred during registry removal: $($_.Exception.Message)"
    exit 1
}

# --- Phase 3: Remove physical files from disk ---
try {
    Write-Host "`nPhase 3: Removing agent installation directory..."
    if (Test-Path $targetInstallDir) {
        Write-Host "Deleting directory: $targetInstallDir"
        Remove-Item -Path $targetInstallDir -Recurse -Force
    }
    Write-Host -ForegroundColor Green "[SUCCESS] Installation directory removed."
} catch {
Write-Host -ForegroundColor Cyan "`n--- Surgical Removal Complete ---"it 1
}

Write-Host -ForegroundColor Cyan "`n--- Surgical Removal Complete ---"
exit 0