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
# Removed unused variable $TargetFreeSpaceGB

# Enhanced logging function
function Write-ImmyLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "Info"    { "[INFO]" }
        "Warning" { "[WARN]" }
        "Error"   { "[ERROR]" }
        "Success" { "[SUCCESS]" }
        "Debug"   { "[DEBUG]" }
    }
    
    $logMessage = "$timestamp $prefix $Message"
    
    # Output to both streams for maximum visibility
    Write-Host $logMessage
    Write-Verbose $logMessage
    
    # Also log to Windows Event Log for persistence
    try {
        $source = "ImmyBot-DiskCleanup"
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName Application -Source $source
        }
        
        $eventType = switch ($Level) {
            "Error"   { "Error" }
            "Warning" { "Warning" }
            default   { "Information" }
        }
        
        Write-EventLog -LogName Application -Source $source -EntryType $eventType -EventId 1001 -Message $logMessage
    } catch {
        # Silently continue if event log writing fails
    }
}

# Function to get folder size safely with detailed logging
function Get-FolderSize {
    param([string]$Path)
    
    Write-ImmyLog -Message "Calculating size for path: $Path" -Level "Debug"
    
    if (Test-Path $Path) {
        try {
            $items = Get-ChildItem $Path -Recurse -File -ErrorAction SilentlyContinue
            $size = ($items | Measure-Object -Property Length -Sum).Sum
            
            if ($size -gt 0) {
                Write-ImmyLog -Message "Path $Path contains $([math]::Round($size/1MB, 2)) MB" -Level "Debug"
            }
            
            return $size
        } catch {
            Write-ImmyLog -Message "Error calculating size for $Path : $($_.Exception.Message)" -Level "Warning"
            return 0
        }
    } else {
        Write-ImmyLog -Message "Path does not exist: $Path" -Level "Debug"
        return 0
    }
}

# Function to get current disk space info with logging
function Get-DiskSpaceInfo {
    Write-ImmyLog -Message "Retrieving current disk space information" -Level "Info"
    
    try {
        $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
        $result = [PSCustomObject]@{
            TotalSpaceGB = [math]::Round($drive.Size / 1GB, 2)
            FreeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            UsedSpaceGB = [math]::Round(($drive.Size - $drive.FreeSpace) / 1GB, 2)
            PercentFree = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)
        }
        
        Write-ImmyLog -Message "Disk Space - Total: $($result.TotalSpaceGB)GB, Free: $($result.FreeSpaceGB)GB, Used: $($result.UsedSpaceGB)GB, Free%: $($result.PercentFree)%" -Level "Info"
        
        return $result
    } catch {
        Write-ImmyLog -Message "Failed to retrieve disk space information: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

# Function to analyze cleanup targets with detailed logging
function Get-CleanupTargets {
    Write-ImmyLog -Message "Analyzing potential cleanup targets" -Level "Info"
    
    $targets = @()
    
    # Define cleanup locations with detailed descriptions
    $cleanupPaths = @(
        @{ Path = "C:\Windows\Temp\*"; Description = "Windows Temp Files"; Category = "System" },
        @{ Path = "$env:TEMP\*"; Description = "User Temp Files"; Category = "User" },
        @{ Path = "C:\Users\*\AppData\Local\Temp\*"; Description = "All Users Temp Files"; Category = "User" },
        @{ Path = "C:\`$Recycle.Bin"; Description = "Recycle Bin"; Category = "User"; Recurse = $true },
        @{ Path = "C:\Windows\SoftwareDistribution\Download\*"; Description = "Windows Update Downloads"; Category = "System" },
        @{ Path = "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*"; Description = "Internet Explorer Cache"; Category = "Browser" },
        @{ Path = "C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\*"; Description = "Web Cache"; Category = "Browser" },
        @{ Path = "C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache\*"; Description = "Chrome Cache"; Category = "Browser" },
        @{ Path = "C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*"; Description = "Firefox Cache"; Category = "Browser" },
        @{ Path = "C:\Windows\Logs\*"; Description = "Windows Logs"; Category = "System" },
        @{ Path = "C:\Windows\Panther\*"; Description = "Windows Setup Logs"; Category = "System" },
        @{ Path = "C:\Windows\Minidump\*"; Description = "Windows Minidumps"; Category = "System" },
        @{ Path = "C:\ProgramData\Microsoft\Windows\WER\*"; Description = "Windows Error Reporting"; Category = "System" }
    )
    
    Write-ImmyLog -Message "Scanning $($cleanupPaths.Count) potential cleanup locations" -Level "Info"
    
    foreach ($item in $cleanupPaths) {
        Write-ImmyLog -Message "Analyzing: $($item.Description) at $($item.Path)" -Level "Debug"
        
        $basePath = $item.Path.Replace("*", "")
        $size = Get-FolderSize -Path $basePath
        
        if ($size -gt 0) {
            $target = [PSCustomObject]@{
                Path = $item.Path
                Description = $item.Description
                Category = $item.Category
                SizeMB = [math]::Round($size / 1MB, 2)
                SizeGB = [math]::Round($size / 1GB, 2)
                Recurse = $item.Recurse -eq $true
            }
            
            $targets += $target
            Write-ImmyLog -Message "Found cleanup target: $($item.Description) - $($target.SizeMB) MB" -Level "Info"
        } else {
            Write-ImmyLog -Message "No content found for: $($item.Description)" -Level "Debug"
        }
    }
    
    $totalPotential = ($targets | Measure-Object -Property SizeGB -Sum).Sum
    Write-ImmyLog -Message "Total potential cleanup space: $([math]::Round($totalPotential, 2)) GB across $($targets.Count) targets" -Level "Info"
    
    return $targets | Sort-Object SizeMB -Descending
}

Write-ImmyLog -Message "=== DISK CLEANUP SCRIPT STARTING ===" -Level "Info"
Write-ImmyLog -Message "Method: $Method" -Level "Info"
Write-ImmyLog -Message "Computer: $env:COMPUTERNAME" -Level "Info"
Write-ImmyLog -Message "User Context: $(whoami)" -Level "Debug"

switch ($Method) {
    "Get" {
        Write-ImmyLog -Message "=== EXECUTING GET MODE ===" -Level "Info"
        
        try {
            # Get current disk space
            $diskSpace = Get-DiskSpaceInfo
            
            # Get cleanup targets
            $cleanupTargets = Get-CleanupTargets
            $totalCleanupPotentialGB = ($cleanupTargets | Measure-Object -Property SizeGB -Sum).Sum
            
            Write-ImmyLog -Message "Analysis complete - $($cleanupTargets.Count) targets identified" -Level "Success"
            
            # Create detailed summary
            $result = [PSCustomObject]@{
                DiskSpace = $diskSpace
                CleanupTargets = $cleanupTargets
                TotalCleanupPotentialGB = [math]::Round($totalCleanupPotentialGB, 2)
                CriticalThresholdGB = $CriticalThresholdGB
                WarningThresholdGB = $WarningThresholdGB
                AnalysisTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                TargetsByCategory = $cleanupTargets | Group-Object Category | ForEach-Object {
                    [PSCustomObject]@{
                        Category = $_.Name
                        Count = $_.Count
                        TotalSizeMB = [math]::Round(($_.Group | Measure-Object -Property SizeMB -Sum).Sum, 2)
                    }
                }
            }
            
            Write-ImmyLog -Message "GET operation completed successfully" -Level "Success"
            return $result
            
        } catch {
            Write-ImmyLog -Message "GET operation failed: $($_.Exception.Message)" -Level "Error"
            throw
        }
    }
    
    "Test" {
        Write-ImmyLog -Message "=== EXECUTING TEST MODE ===" -Level "Info"
        
        try {
            # Get current disk space
            $diskSpace = Get-DiskSpaceInfo
            
            Write-ImmyLog -Message "Testing against thresholds - Critical: ${CriticalThresholdGB}GB, Warning: ${WarningThresholdGB}GB" -Level "Info"
            
            # Test conditions with detailed logging
            if ($diskSpace.FreeSpaceGB -lt $CriticalThresholdGB) {
                Write-ImmyLog -Message "CRITICAL: Disk space is critically low! ($($diskSpace.FreeSpaceGB)GB < ${CriticalThresholdGB}GB)" -Level "Error"
                Write-ImmyLog -Message "TEST result: FAIL - Critical threshold breached" -Level "Error"
                return $false
            }
            elseif ($diskSpace.FreeSpaceGB -lt $WarningThresholdGB) {
                Write-ImmyLog -Message "WARNING: Disk space is low ($($diskSpace.FreeSpaceGB)GB < ${WarningThresholdGB}GB)" -Level "Warning"
                Write-ImmyLog -Message "TEST result: FAIL - Warning threshold breached" -Level "Warning"
                return $false
            }
            else {
                Write-ImmyLog -Message "PASS: Disk space is adequate ($($diskSpace.FreeSpaceGB)GB > ${WarningThresholdGB}GB)" -Level "Success"
                Write-ImmyLog -Message "TEST result: PASS - Sufficient disk space available" -Level "Success"
                return $true
            }
            
        } catch {
            Write-ImmyLog -Message "TEST operation failed: $($_.Exception.Message)" -Level "Error"
            throw
        }
    }
    
    "Set" {
        Write-ImmyLog -Message "=== EXECUTING SET MODE ===" -Level "Info"
        
        try {
            # Get initial disk space
            $initialDiskSpace = Get-DiskSpaceInfo
            Write-ImmyLog -Message "Initial state: $($initialDiskSpace.FreeSpaceGB)GB free" -Level "Info"
            
            $totalFreed = 0
            $operationsPerformed = @()
            
            # Function to safely remove items with comprehensive logging
            function Remove-CleanupItems {
                param(
                    [string]$Path,
                    [string]$Description,
                    [string]$Category,
                    [switch]$Recurse
                )
                
                Write-ImmyLog -Message "Starting cleanup: $Description ($Category)" -Level "Info"
                
                if (Test-Path $Path) {
                    $sizeBefore = Get-FolderSize $Path
                    Write-ImmyLog -Message "  Path: $Path" -Level "Debug"
                    Write-ImmyLog -Message "  Size before: $([math]::Round($sizeBefore/1MB, 2)) MB" -Level "Info"
                    
                    try {
                        $itemCount = 0
                        if ($Recurse) {
                            $items = Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue
                            $itemCount = $items.Count
                            $items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                        } else {
                            $items = Get-ChildItem $Path -Force -ErrorAction SilentlyContinue
                            $itemCount = $items.Count
                            $items | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                        }
                        
                        $sizeAfter = Get-FolderSize $Path
                        $freed = $sizeBefore - $sizeAfter
                        
                        $operation = [PSCustomObject]@{
                            Description = $Description
                            Category = $Category
                            ItemsProcessed = $itemCount
                            SizeBeforeMB = [math]::Round($sizeBefore/1MB, 2)
                            SizeAfterMB = [math]::Round($sizeAfter/1MB, 2)
                            FreedMB = [math]::Round($freed/1MB, 2)
                            Success = $true
                        }
                        
                        Write-ImmyLog -Message "  Processed $itemCount items" -Level "Info"
                        Write-ImmyLog -Message "  Freed: $([math]::Round($freed/1MB, 2)) MB" -Level "Success"
                        
                        return $freed, $operation
                        
                    } catch {
                        $operation = [PSCustomObject]@{
                            Description = $Description
                            Category = $Category
                            Error = $_.Exception.Message
                            Success = $false
                        }
                        
                        Write-ImmyLog -Message "  Error: $($_.Exception.Message)" -Level "Error"
                        return 0, $operation
                    }
                } else {
                    Write-ImmyLog -Message "  Path not found, skipping: $Description" -Level "Debug"
                    
                    $operation = [PSCustomObject]@{
                        Description = $Description
                        Category = $Category
                        Result = "Path not found"
                        Success = $true
                    }
                    
                    return 0, $operation
                }
            }
            
            # Execute cleanup operations with detailed tracking
            Write-ImmyLog -Message "Beginning cleanup operations" -Level "Info"
            
            $cleanupOperations = @(
                @{ Path = "C:\Windows\Temp\*"; Description = "Windows Temp Files"; Category = "System" },
                @{ Path = "$env:TEMP\*"; Description = "User Temp Files"; Category = "User" },
                @{ Path = "C:\Users\*\AppData\Local\Temp\*"; Description = "All Users Temp Files"; Category = "User" },
                @{ Path = "C:\`$Recycle.Bin"; Description = "Recycle Bin"; Category = "User"; Recurse = $true },
                @{ Path = "C:\Windows\SoftwareDistribution\Download\*"; Description = "Windows Update Downloads"; Category = "System" },
                @{ Path = "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*"; Description = "Internet Explorer Cache"; Category = "Browser" },
                @{ Path = "C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\*"; Description = "Web Cache"; Category = "Browser" },
                @{ Path = "C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache\*"; Description = "Chrome Cache"; Category = "Browser" },
                @{ Path = "C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*"; Description = "Firefox Cache"; Category = "Browser" },
                @{ Path = "C:\Windows\Logs\*"; Description = "Windows Logs"; Category = "System" },
                @{ Path = "C:\Windows\Panther\*"; Description = "Windows Setup Logs"; Category = "System" },
                @{ Path = "C:\Windows\Minidump\*"; Description = "Windows Minidumps"; Category = "System" },
                @{ Path = "C:\Windows\memory.dmp"; Description = "Windows Memory Dump"; Category = "System" },
                @{ Path = "C:\ProgramData\Microsoft\Windows\WER\*"; Description = "Windows Error Reporting"; Category = "System" }
            )
            
            foreach ($operation in $cleanupOperations) {
                $freed, $opResult = Remove-CleanupItems -Path $operation.Path -Description $operation.Description -Category $operation.Category -Recurse:$operation.Recurse
                $totalFreed += $freed
                $operationsPerformed += $opResult
            }
            
            # Clear event logs older than 30 days
            Write-ImmyLog -Message "Clearing old Event Logs (>30 days)" -Level "Info"
            $eventLogsCleaned = 0
            try {
                wevtutil el | ForEach-Object {
                    $logName = $_
                    try {
                        $events = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction SilentlyContinue
                        if ($events -and $events[0].TimeCreated -lt (Get-Date).AddDays(-30)) {
                            wevtutil cl $logName
                            $eventLogsCleaned++
                            Write-ImmyLog -Message "  Cleared: $logName" -Level "Debug"
                        }
                    } catch {
                        # Skip logs that can't be accessed
                    }
                }
                Write-ImmyLog -Message "Cleared $eventLogsCleaned event logs" -Level "Info"
            } catch {
                Write-ImmyLog -Message "Error clearing event logs: $($_.Exception.Message)" -Level "Warning"
            }
            
            # Run built-in Disk Cleanup
            Write-ImmyLog -Message "Running Windows built-in Disk Cleanup" -Level "Info"
            try {
                # Set registry keys for automatic cleanup
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
                $cleanupKeys = @(
                    "Active Setup Temp Folders", "BranchCache", "Downloaded Program Files",
                    "Internet Cache Files", "Offline Pages Files", "Old ChkDsk Files",
                    "Previous Installations", "Recycle Bin", "Setup Log Files",
                    "System error memory dump files", "System error minidump files",
                    "Temporary Files", "Temporary Setup Files", "Thumbnail Cache",
                    "Update Cleanup", "Windows Error Reporting Archive Files",
                    "Windows Error Reporting Queue Files", "Windows Error Reporting System Archive Files",
                    "Windows Error Reporting System Queue Files", "Windows Upgrade Log Files"
                )
                
                # Enable cleanup categories
                $keysConfigured = 0
                foreach ($key in $cleanupKeys) {
                    $keyPath = Join-Path $regPath $key
                    if (Test-Path $keyPath) {
                        Set-ItemProperty -Path $keyPath -Name "StateFlags0001" -Value 2 -ErrorAction SilentlyContinue
                        $keysConfigured++
                    }
                }
                
                Write-ImmyLog -Message "Configured $keysConfigured cleanup categories" -Level "Debug"
                
                # Run cleanmgr
                $cleanmgrProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow -PassThru
                Write-ImmyLog -Message "Disk Cleanup completed with exit code: $($cleanmgrProcess.ExitCode)" -Level "Info"
                
            } catch {
                Write-ImmyLog -Message "Error running built-in Disk Cleanup: $($_.Exception.Message)" -Level "Warning"
            }
            
            # Get final disk space and calculate results
            $finalDiskSpace = Get-DiskSpaceInfo
            $actualFreed = $finalDiskSpace.FreeSpaceGB - $initialDiskSpace.FreeSpaceGB
            
            # Create comprehensive summary
            Write-ImmyLog -Message "=== CLEANUP SUMMARY ===" -Level "Info"
            Write-ImmyLog -Message "Manual cleanup freed: $([math]::Round($totalFreed/1MB, 2)) MB" -Level "Info"
            Write-ImmyLog -Message "Total space gained: $([math]::Round($actualFreed, 2)) GB" -Level "Info"
            Write-ImmyLog -Message "Free space before: $($initialDiskSpace.FreeSpaceGB) GB" -Level "Info"
            Write-ImmyLog -Message "Free space after: $($finalDiskSpace.FreeSpaceGB) GB" -Level "Info"
            Write-ImmyLog -Message "Percent free: $($finalDiskSpace.PercentFree)%" -Level "Info"
            Write-ImmyLog -Message "Event logs cleaned: $eventLogsCleaned" -Level "Info"
            
            # Determine success level
            $cleanupSuccessful = $finalDiskSpace.FreeSpaceGB -gt $WarningThresholdGB
            if ($cleanupSuccessful) {
                Write-ImmyLog -Message "SUCCESS: Disk space is now above warning threshold!" -Level "Success"
            } elseif ($finalDiskSpace.PercentFree -lt 10) {
                Write-ImmyLog -Message "WARNING: C: drive is still critically low on space!" -Level "Warning"
                Write-ImmyLog -Message "Consider additional cleanup or moving files to another drive." -Level "Warning"
            } else {
                Write-ImmyLog -Message "Cleanup completed but still below warning threshold" -Level "Warning"
            }
            
            # Return comprehensive results
            $result = [PSCustomObject]@{
                InitialDiskSpace = $initialDiskSpace
                FinalDiskSpace = $finalDiskSpace
                SpaceFreedGB = [math]::Round($actualFreed, 2)
                ManualCleanupMB = [math]::Round($totalFreed/1MB, 2)
                CleanupSuccessful = $cleanupSuccessful
                OperationsPerformed = $operationsPerformed
                EventLogsCleaned = $eventLogsCleaned
                CompletedTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Summary = @{
                    TotalOperations = $operationsPerformed.Count
                    SuccessfulOperations = ($operationsPerformed | Where-Object Success).Count
                    FailedOperations = ($operationsPerformed | Where-Object { -not $_.Success }).Count
                    CategoriesCleaned = ($operationsPerformed | Where-Object Success | Group-Object Category).Name
                }
            }
            
            Write-ImmyLog -Message "SET operation completed successfully" -Level "Success"
            return $result
            
        } catch {
            Write-ImmyLog -Message "SET operation failed: $($_.Exception.Message)" -Level "Error"
            throw
        }
    }
}

Write-ImmyLog -Message "=== DISK CLEANUP SCRIPT COMPLETED ===" -Level "Info"