# =================================================================================
# Name:     C9-ImmyAgent-Uninstall-Forceful.ps1
# Purpose:  Forcefully removes the ImmyBot Agent, its files, and its
#           service registration to break all self-repair loops.
# Author:   Josh Phillips
# Date:     08/11/2025
# Version:  4.2
# =================================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProductCode
)

# Coalesce from Ninja form variable if not provided as a script parameter
if (-not $PSBoundParameters.ContainsKey('ProductCode') -or [string]::IsNullOrWhiteSpace($ProductCode)) {
    $ProductCode = $env:productCode
}
if ([string]::IsNullOrWhiteSpace($ProductCode)) {
    # Fallback to legacy hardcoded value for safety
    $ProductCode = "{67F85C1E-29B2-45A6-ABC4-6E198888AEEC}"
}
$ProductCode = $ProductCode.Trim()
Write-Host -ForegroundColor Cyan "Using ProductCode: $ProductCode"

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# --- Configuration: Static from current Agent details. Will make dynamic later if needed ---
$targetProductCode              = $ProductCode
$targetProductName              = "ImmyBot Agent"
$targetServiceName              = "ImmyBot Agent"
$targetProcessName              = "ImmyBot.Agent"
$targetInstallDir               = "C:\Program Files (x86)\ImmyBot"
$targetProgramDataDir           = "C:\ProgramData\ImmyBot"
$targetProgramDataServiceDir    = "C:\ProgramData\ImmyBotAgentService"

Write-Host -ForegroundColor Cyan "--- Starting Surgical Removal of '$targetProductName' ---"

# --- Phase 1: Terminate and DELETE all services and processes ---
try {
    Write-Host "Phase 1: Terminating agent services and processes..."
    # Service presence
    $svc = Get-Service -Name $targetServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host -ForegroundColor Yellow "Service '$targetServiceName' found (Status: $($svc.Status)). Attempting to stop..."
        $svc | Stop-Service -Force -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Green "Stop command issued for service '$targetServiceName'."
    } else {
        Write-Host -ForegroundColor Yellow "Service '$targetServiceName' not found. Nothing to stop."
    }

    # Process presence
    $proc = Get-Process -Name $targetProcessName -ErrorAction SilentlyContinue
    if ($proc) {
        $procCount = @($proc).Count
        Write-Host -ForegroundColor Yellow "Process '$targetProcessName' found (Instances: $procCount). Attempting to stop..."
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Green "Stop command issued for process '$targetProcessName'."
    } else {
        Write-Host -ForegroundColor Yellow "Process '$targetProcessName' not found. Nothing to stop."
    }
    
    $serviceCheck = Get-Service -Name $targetServiceName -ErrorAction SilentlyContinue
    if ($serviceCheck) {
        Write-Host -ForegroundColor Yellow "Service '$targetServiceName' still registered. Attempting to delete via sc.exe..."
        $deleteResult = Start-Process -FilePath "sc.exe" -ArgumentList "delete `"$targetServiceName`"" -Wait -PassThru
        if ($deleteResult.ExitCode -eq 0 -or $deleteResult.ExitCode -eq 1060) {
            Write-Host -ForegroundColor Green "Service '$targetServiceName' deletion attempted. ExitCode: $($deleteResult.ExitCode)."
        } else {
            throw "sc.exe failed to delete service '$targetServiceName' (ExitCode: $($deleteResult.ExitCode))."
        }
    } else {
        Write-Host -ForegroundColor Yellow "Service '$targetServiceName' is not registered. No deletion needed."
    }
    
    Write-Host -ForegroundColor Green "[SUCCESS] Phase 1: All processes and services terminated and deleted."
} catch {
    Write-Warning "A non-fatal error occurred during termination/deletion. Error: $($_.Exception.Message)"
}

# --- Phase 2: Surgically remove Windows Installer registry keys ---
try {
    Write-Host "`nPhase 2: Removing Windows Installer registry registrations..."
    Write-Host -ForegroundColor Cyan "Target Product Code: $targetProductCode"
    
    # Helper function to convert standard GUID to packed format used in Installer\Products
    function ConvertTo-PackedGuid {
        param([string]$Guid)
        
        $parts = $Guid.Trim('{}').Split('-')
        
        # Part 1 (8 chars) - reversed
        $p1_chars = $parts[0].ToCharArray()
        [array]::Reverse($p1_chars)
        $p1 = -join $p1_chars

        # Part 2 (4 chars) - reversed
        $p2_chars = $parts[1].ToCharArray()
        [array]::Reverse($p2_chars)
        $p2 = -join $p2_chars
        
        # Part 3 (4 chars) - reversed
        $p3_chars = $parts[2].ToCharArray()
        [array]::Reverse($p3_chars)
        $p3 = -join $p3_chars
        
        # Parts 4 and 5 are byte-swapped, which means reversing each pair of characters.
        $p4_chars = $parts[3].ToCharArray()
        $p4 = -join ($p4_chars[1], $p4_chars[0], $p4_chars[3], $p4_chars[2])
        
        $p5_chars = $parts[4].ToCharArray()
        $p5 = -join ($p5_chars[1], $p5_chars[0], $p5_chars[3], $p5_chars[2], $p5_chars[5], $p5_chars[4], $p5_chars[7], $p5_chars[6], $p5_chars[9], $p5_chars[8], $p5_chars[11], $p5_chars[10])

        return "$p1$p2$p3$p4$p5".ToUpper()
    }
    
    $packedGuid = ConvertTo-PackedGuid -Guid $targetProductCode
    Write-Host -ForegroundColor Cyan "Packed GUID (Installer\Products key): $packedGuid"

    $uninstallKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$targetProductCode"
    $installerProductKeyPath = "HKLM:\SOFTWARE\Classes\Installer\Products\$packedGuid"

    if (Test-Path $uninstallKeyPath) {
        Write-Host -ForegroundColor Yellow "Found Uninstall key at '$uninstallKeyPath'. Removing..."
        Remove-Item -Path $uninstallKeyPath -Recurse -Force
        Write-Host -ForegroundColor Green "Removed Uninstall key '$uninstallKeyPath'."
    } else {
        Write-Host -ForegroundColor Yellow "Uninstall key not found at '$uninstallKeyPath'."
    }

    if (Test-Path $installerProductKeyPath) {
        Write-Host -ForegroundColor Yellow "Found Installer Product key at '$installerProductKeyPath'. Removing..."
        Remove-Item -Path $installerProductKeyPath -Recurse -Force
        Write-Host -ForegroundColor Green "Removed Installer Product key '$installerProductKeyPath'."
    } else {
        Write-Host -ForegroundColor Yellow "Installer Product key not found at '$installerProductKeyPath'."
    }
    
    Write-Host -ForegroundColor Green "[SUCCESS] Phase 2: Registry keys surgically removed."
} catch {
    Write-Error "A fatal error occurred during registry removal: $($_.Exception.Message)"
    exit 1
}

# --- Phase 3: Remove physical files from disk ---
try {
    Write-Host "`nPhase 3: Removing agent installation directory..."
    if (Test-Path $targetInstallDir) {
        Write-Host -ForegroundColor Yellow "Found install directory '$targetInstallDir'. Removing..."
        Remove-Item -Path $targetInstallDir -Recurse -Force
        Write-Host -ForegroundColor Green "Removed install directory '$targetInstallDir'."
    } else {
        Write-Host -ForegroundColor Yellow "Install directory not found at '$targetInstallDir'."
    }
    Write-Host -ForegroundColor Green "[SUCCESS] Phase 3: Installation directory removal step complete."
} catch {
    Write-Error "A fatal error occurred during file system cleanup: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "`nPhase 3: Removing ProgramData directory..."
    if (Test-Path $targetProgramDataDir) {
        Write-Host -ForegroundColor Yellow "Found ProgramData directory '$targetProgramDataDir'. Removing..."
        Remove-Item -Path $targetProgramDataDir -Recurse -Force
        Write-Host -ForegroundColor Green "Removed ProgramData directory '$targetProgramDataDir'."
    } else {
        Write-Host -ForegroundColor Yellow "ProgramData directory not found at '$targetProgramDataDir'."
    }
    Write-Host -ForegroundColor Green "[SUCCESS] Phase 3: ProgramData directory removal step complete."
} catch {
    Write-Error "A fatal error occurred during file system cleanup: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "`nPhase 3: Removing ProgramData directory for ImmyBotAgentService..."
    if (Test-Path $targetProgramDataServiceDir) {
        Write-Host -ForegroundColor Yellow "Found ProgramData directory '$targetProgramDataServiceDir'. Removing..."
        Remove-Item -Path $targetProgramDataServiceDir -Recurse -Force
        Write-Host -ForegroundColor Green "Removed ProgramData directory '$targetProgramDataServiceDir'."
    } else {
        Write-Host -ForegroundColor Yellow "ProgramData directory not found at '$targetProgramDataServiceDir'."
    }
    Write-Host -ForegroundColor Green "[SUCCESS] Phase 3: ImmyBotAgentService ProgramData directory removal step complete."
} catch {
    Write-Error "A fatal error occurred during file system cleanup: $($_.Exception.Message)"
    exit 1
}

# --- Phase 4: Final Verification ---
Write-Host "`nPhase 4: Performing final verification..."
Start-Sleep -Seconds 5

$finalServiceCheck = Get-Service -Name $targetServiceName -ErrorAction SilentlyContinue
if ($finalServiceCheck) {
    Write-Error "[FAIL] Verification Failed: The service '$targetServiceName' still exists!"
    exit 1
}

# Verify process is not running
$finalProcCheck = Get-Process -Name $targetProcessName -ErrorAction SilentlyContinue
if ($finalProcCheck) {
    $count = @($finalProcCheck).Count
    Write-Error "[FAIL] Verification Failed: Process '$targetProcessName' still running (Instances: $count)."
    exit 1
} else {
    Write-Host -ForegroundColor Green "[OK] No running process named '$targetProcessName'."
}

# Optional additional verification and reporting
if (Test-Path $targetInstallDir) {
    Write-Error "[FAIL] Verification Failed: Install directory still present at '$targetInstallDir'."
    exit 1
} else {
    Write-Host -ForegroundColor Green "[OK] Install directory '$targetInstallDir' not found."
}

if (Test-Path $targetProgramDataDir) {
    Write-Error "[FAIL] Verification Failed: ProgramData directory still present at '$targetProgramDataDir'."
    exit 1
} else {
    Write-Host -ForegroundColor Green "[OK] ProgramData directory '$targetProgramDataDir' not found."
}

if (Test-Path $targetProgramDataServiceDir) {
    Write-Error "[FAIL] Verification Failed: ProgramData directory still present at '$targetProgramDataServiceDir'."
    exit 1
} else {
    Write-Host -ForegroundColor Green "[OK] ProgramData directory '$targetProgramDataServiceDir' not found."
}

# Verify registry keys are gone
if (Test-Path $uninstallKeyPath) {
    Write-Error "[FAIL] Verification Failed: Uninstall registry key still present at '$uninstallKeyPath'."
    exit 1
} else {
    Write-Host -ForegroundColor Green "[OK] Uninstall registry key '$uninstallKeyPath' not found."
}

if (Test-Path $installerProductKeyPath) {
    Write-Error "[FAIL] Verification Failed: Installer Product key still present at '$installerProductKeyPath'."
    exit 1
} else {
    Write-Host -ForegroundColor Green "[OK] Installer Product key '$installerProductKeyPath' not found."
}

Write-Host -ForegroundColor Cyan "`n--- [SUCCESS] Surgical Removal and Verification Complete ---"
exit 0