#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disk cleanup script using Get/Test/Set methodology for ImmyBot
.DESCRIPTION
    Get: Analyzes disk space and potential cleanup targets
    Test: Determines if cleanup is needed based on free space thresholds  
    Set: Performs comprehensive disk cleanup
.PARAMETER Method
    Specifies the operation mode: Get, Test, or Set
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Get", "Test", "Set")]
    [string]$Method
)

# Configuration
$CriticalThresholdGB = 2     # Less than 2GB free = critical
$WarningThresholdGB = 10     # Less than 10GB free = warning

# ImmyBot-compatible logging function - uses Write-Verbose to avoid stdout pollution
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Use Write-Verbose for all logging to avoid corrupting ImmyBot stdout
    Write-Verbose $logMessage -Verbose
}

# Function to get current disk space info
function Get-DiskSpaceInfo {
    Write-Log -Message "Retrieving disk space information"
    
    try {
        $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
        if (-not $drive) {
            throw "Unable to retrieve C: drive information"
        }
        
        $result = [PSCustomObject]@{
            TotalSpaceGB = [math]::Round($drive.Size / 1GB, 2)
            FreeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            UsedSpaceGB = [math]::Round(($drive.Size - $drive.FreeSpace) / 1GB, 2)
            PercentFree = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)
        }
        
        Write-Log -Message "Disk Space - Total: $($result.TotalSpaceGB)GB, Free: $($result.FreeSpaceGB)GB, Used: $($result.UsedSpaceGB)GB, Free%: $($result.PercentFree)%"
        return $result
        
    } catch {
        throw "Failed to retrieve disk space information: $($_.Exception.Message)"
    }
}

# Function to get folder size safely
function Get-FolderSizeMB {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            $items = Get-ChildItem $Path -Recurse -File -ErrorAction SilentlyContinue
            $size = ($items | Measure-Object -Property Length -Sum).Sum
            return [math]::Round($size / 1MB, 2)
        } catch {
            Write-Log -Message "Error calculating size for $Path : $($_.Exception.Message)" -Level "Warning"
            return 0
        }
    }
    return 0
}

# Function to safely remove items with progress tracking
function Remove-CleanupItems {
    param(
        [string]$Path,
        [string]$Description
    )
    
    if (-not (Test-Path $Path)) {
        Write-Log -Message "Path not found, skipping: $Description" -Level "Info"
        return 0
    }
    
    $sizeBefore = Get-FolderSizeMB $Path
    Write-Log -Message "Cleaning: $Description (Size: $sizeBefore MB)"
    
    try {
        $items = Get-ChildItem $Path -Force -ErrorAction SilentlyContinue
        $itemCount = $items.Count
        $items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        
        $sizeAfter = Get-FolderSizeMB $Path
        $freed = $sizeBefore - $sizeAfter
        
        Write-Log -Message "  Processed $itemCount items, freed $freed MB" -Level "Success"
        return $freed
        
    } catch {
        Write-Log -Message "  Error cleaning $Description : $($_.Exception.Message)" -Level "Error"
        return 0
    }
}

Write-Log -Message "=== DISK CLEANUP SCRIPT STARTING ===" -Level "Info"
Write-Log -Message "Method: $Method, Computer: $env:COMPUTERNAME"

switch ($Method) {
    "Get" {
        Write-Log -Message "=== EXECUTING GET MODE ===" -Level "Info"
        
        try {
            $diskSpace = Get-DiskSpaceInfo
            
            # Define cleanup targets for analysis
            $cleanupTargets = @(
                @{ Path = "C:\Windows\Temp"; Description = "Windows Temp Files" },
                @{ Path = $env:TEMP; Description = "User Temp Files" },
                @{ Path = "C:\Users\*\AppData\Local\Temp"; Description = "All Users Temp Files" },
                @{ Path = "C:\`$Recycle.Bin"; Description = "Recycle Bin" },
                @{ Path = "C:\Windows\SoftwareDistribution\Download"; Description = "Windows Update Downloads" },
                @{ Path = "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache"; Description = "Internet Cache" },
                @{ Path = "C:\Windows\Logs"; Description = "Windows Logs" },
                @{ Path = "C:\Windows\Minidump"; Description = "Windows Minidumps" }
            )
            
            $analyzedTargets = @()
            $totalCleanupPotentialMB = 0
            
            foreach ($target in $cleanupTargets) {
                $sizeMB = Get-FolderSizeMB $target.Path
                if ($sizeMB -gt 0) {
                    $analyzedTargets += [PSCustomObject]@{
                        Path = $target.Path
                        Description = $target.Description
                        SizeMB = $sizeMB
                    }
                    $totalCleanupPotentialMB += $sizeMB
                }
            }
            
            Write-Log -Message "Analysis complete - $($analyzedTargets.Count) targets identified, $([math]::Round($totalCleanupPotentialMB/1024, 2)) GB potential cleanup" -Level "Success"
            
            # Return clean object for ImmyBot (no extra output)
            return [PSCustomObject]@{
                DiskSpace = $diskSpace
                CleanupTargets = $analyzedTargets
                TotalCleanupPotentialGB = [math]::Round($totalCleanupPotentialMB/1024, 2)
                CriticalThresholdGB = $CriticalThresholdGB
                WarningThresholdGB = $WarningThresholdGB
                AnalysisTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
        } catch {
            throw "GET operation failed: $($_.Exception.Message)"
        }
    }
    
    "Test" {
        Write-Log -Message "=== EXECUTING TEST MODE ===" -Level "Info"
        
        try {
            $diskSpace = Get-DiskSpaceInfo
            
            Write-Log -Message "Testing thresholds - Critical: ${CriticalThresholdGB}GB, Warning: ${WarningThresholdGB}GB"
            
            if ($diskSpace.FreeSpaceGB -lt $CriticalThresholdGB) {
                Write-Log -Message "CRITICAL: Disk space critically low ($($diskSpace.FreeSpaceGB)GB < ${CriticalThresholdGB}GB)" -Level "Error"
                return $false
            }
            elseif ($diskSpace.FreeSpaceGB -lt $WarningThresholdGB) {
                Write-Log -Message "WARNING: Disk space low ($($diskSpace.FreeSpaceGB)GB < ${WarningThresholdGB}GB)" -Level "Warning"
                return $false
            }
            else {
                Write-Log -Message "PASS: Disk space adequate ($($diskSpace.FreeSpaceGB)GB > ${WarningThresholdGB}GB)" -Level "Success"
                return $true
            }
            
        } catch {
            throw "TEST operation failed: $($_.Exception.Message)"
        }
    }
    
    "Set" {
        Write-Log -Message "=== EXECUTING SET MODE ===" -Level "Info"
        
        try {
            $initialDiskSpace = Get-DiskSpaceInfo
            Write-Log -Message "Initial free space: $($initialDiskSpace.FreeSpaceGB)GB"
            
            $totalFreedMB = 0
            $operationsPerformed = @()
            
            # Execute cleanup operations
            $cleanupOperations = @(
                @{ Path = "C:\Windows\Temp\*"; Description = "Windows Temp Files" },
                @{ Path = "$env:TEMP\*"; Description = "User Temp Files" },
                @{ Path = "C:\Users\*\AppData\Local\Temp\*"; Description = "All Users Temp Files" },
                @{ Path = "C:\`$Recycle.Bin\*"; Description = "Recycle Bin" },
                @{ Path = "C:\Windows\SoftwareDistribution\Download\*"; Description = "Windows Update Downloads" },
                @{ Path = "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*"; Description = "Internet Cache" },
                @{ Path = "C:\Windows\Logs\*"; Description = "Windows Logs" },
                @{ Path = "C:\Windows\Minidump\*"; Description = "Windows Minidumps" }
            )
            
            foreach ($operation in $cleanupOperations) {
                $freed = Remove-CleanupItems -Path $operation.Path -Description $operation.Description
                $totalFreedMB += $freed
                $operationsPerformed += $operation.Description
            }
            
            # Run built-in Disk Cleanup
            Write-Log -Message "Running Windows Disk Cleanup"
            try {
                Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:65535" -Wait -NoNewWindow
                Write-Log -Message "Built-in Disk Cleanup completed" -Level "Success"
            } catch {
                Write-Log -Message "Error running built-in Disk Cleanup: $($_.Exception.Message)" -Level "Warning"
            }
            
            # Get final results
            $finalDiskSpace = Get-DiskSpaceInfo
            $actualFreedGB = $finalDiskSpace.FreeSpaceGB - $initialDiskSpace.FreeSpaceGB
            $cleanupSuccessful = $finalDiskSpace.FreeSpaceGB -gt $WarningThresholdGB
            
            Write-Log -Message "=== CLEANUP SUMMARY ===" -Level "Info"
            Write-Log -Message "Manual cleanup freed: $([math]::Round($totalFreedMB/1024, 2)) GB"
            Write-Log -Message "Total space gained: $([math]::Round($actualFreedGB, 2)) GB"
            Write-Log -Message "Final free space: $($finalDiskSpace.FreeSpaceGB) GB ($($finalDiskSpace.PercentFree)%)"
            
            if ($cleanupSuccessful) {
                Write-Log -Message "SUCCESS: Disk space now above warning threshold" -Level "Success"
            } else {
                Write-Log -Message "WARNING: Disk space still below threshold after cleanup" -Level "Warning"
            }
            
            # Return clean results object for ImmyBot
            return [PSCustomObject]@{
                InitialFreeSpaceGB = $initialDiskSpace.FreeSpaceGB
                FinalFreeSpaceGB = $finalDiskSpace.FreeSpaceGB
                SpaceFreedGB = [math]::Round($actualFreedGB, 2)
                ManualCleanupMB = [math]::Round($totalFreedMB, 2)
                FinalPercentFree = $finalDiskSpace.PercentFree
                CleanupSuccessful = $cleanupSuccessful
                OperationsPerformed = $operationsPerformed
                CompletedTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
        } catch {
            throw "SET operation failed: $($_.Exception.Message)"
        }
    }
}

Write-Log -Message "=== DISK CLEANUP SCRIPT COMPLETED ===" -Level "Info"