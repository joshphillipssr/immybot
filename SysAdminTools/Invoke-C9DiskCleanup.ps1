<#
.SYNOPSIS
    A Get/Test/Set task script for performing comprehensive disk cleanup on a Windows endpoint.
.DESCRIPTION
    - Get:   Retrieves the current C: drive free space percentage.
    - Test:  Fails if the free space is below a defined threshold.
    - Set:   Executes a deep cleanup of temporary files, caches, logs, and runs the built-in Windows Disk Cleanup utility.
.PARAMETER Method
    Specifies the operational mode: Get, Test, or Set.
.INPUTS
    For 'Test' method, expects a $Configuration object from the 'Get' method.
.OUTPUTS
    - Get:   A PSCustomObject with disk space details.
    - Test:  Boolean $true or $false.
    - Set:   Boolean $true on successful execution.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Test", "Set")]
    [string]$Method
)

# --- SCRIPT BODY ---
switch ($Method) {
    'Get' {
        Write-Host "--- [GET] Checking C: Drive Space ---"
        $diskInfo = Invoke-ImmyCommand -ScriptBlock {
            $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
            if (-not $drive) {
                Write-Error "Could not retrieve C: drive information."
                return $null
            }

            return @{
                TotalSizeGB = [math]::Round($drive.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
                PercentFree = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)
            }
        }

        if ($diskInfo) {
            Write-Host ("Disk Info Found: {0} GB Free ({1}%)" -f $diskInfo.FreeSpaceGB, $diskInfo.PercentFree)
            return [PSCustomObject]$diskInfo
        }
        else {
            Write-Error "Failed to get disk info from the endpoint."
            throw "Get method failed."
        }
    }
    'Test' {
        Write-Host "--- [TEST] Evaluating Disk Space ---"
        # This threshold can be adjusted as needed.
        $LowDiskThresholdPercent = 10

        if (-not $Configuration) {
            throw "Test method requires a valid `$Configuration object from the Get method. Please check task configuration."
        }

        Write-Host ("Comparing free space ({0}%) against threshold ({1}%)" -f $Configuration.PercentFree, $LowDiskThresholdPercent)

        if ($Configuration.PercentFree -lt $LowDiskThresholdPercent) {
            Write-Warning ("Disk space is critically low. Free space is {0}%, which is below the {1}% threshold." -f $Configuration.PercentFree, $LowDiskThresholdPercent)
            return $false # Test fails, triggering the Set method.
        }
        else {
            Write-Host "Disk space is sufficient. Test passes." -ForegroundColor Green
            return $true # Test passes.
        }
    }
    'Set' {
        Write-Host "--- [SET] Initiating Disk Cleanup ---" -ForegroundColor Yellow

        $totalFreedBytes = Invoke-ImmyCommand -ScriptBlock {
            # Helper function to get folder size
            function Get-FolderSize($Path) {
                if (Test-Path $Path -ErrorAction SilentlyContinue) {
                    return (Get-ChildItem $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                }
                return 0
            }

            # Helper function to safely remove items and report back
            function Remove-SafeItem($Path, $Description) {
                if (Test-Path $Path -ErrorAction SilentlyContinue) {
                    $sizeBefore = Get-FolderSize $Path
                    Write-Host "Cleaning: $Description..."
                    try {
                        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1 # Give OS a moment to release handles
                        $sizeAfter = Get-FolderSize $Path
                        $freed = $sizeBefore - $sizeAfter
                        Write-Host ("  Freed: {0} MB" -f ([math]::Round($freed / 1MB, 2))) -ForegroundColor Green
                        return $freed
                    }
                    catch {
                        Write-Warning "  Error cleaning '$Path': $_"
                        return 0
                    }
                }
                return 0
            }

            $totalFreed = 0
            
            # 1. Windows & User Temp folders
            $totalFreed += Remove-SafeItem -Path "$env:SystemRoot\Temp\*" -Description "Windows Temp"
            $totalFreed += Remove-SafeItem -Path "$env:TEMP\*" -Description "Current User Temp"

            # 2. Recycle Bin
            try {
                Write-Host "Cleaning: Recycle Bin..."
                $recycleBin = New-Object -ComObject Shell.Application
                $recycleBin.Namespace(0xA).Items() | ForEach-Object { $recycleBin.Namespace(0xA).ParseName($_.Name).InvokeVerb("delete") }
                Write-Host "  Recycle Bin cleared." -ForegroundColor Green
            } catch {
                Write-Warning "  Could not clear Recycle Bin via COM object. Trying direct removal..."
                $totalFreed += Remove-SafeItem -Path "C:\`$Recycle.Bin" -Description "Recycle Bin (Direct)"
            }

            # 3. Windows Update Cache
            $totalFreed += Remove-SafeItem -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Description "Windows Update Cache"

            # 4. Windows Error Reporting
            $totalFreed += Remove-SafeItem -Path "$env:ProgramData\Microsoft\Windows\WER\*" -Description "Windows Error Reporting Archives"

            # 5. Run built-in Disk Cleanup (cleanmgr)
            Write-Host "Running: Windows Disk Cleanup utility (cleanmgr.exe)..."
            try {
                # Configure cleanmgr to run unattended for all available items
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
                Get-ChildItem -Path $regPath | ForEach-Object {
                    Set-ItemProperty -Path $_.PSPath -Name "StateFlags0001" -Value 2 -ErrorAction SilentlyContinue
                }
                # Execute the cleanup
                $process = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -PassThru -NoNewWindow
                if ($process.ExitCode -eq 0) {
                    Write-Host "  Cleanmgr completed successfully." -ForegroundColor Green
                } else {
                    Write-Warning "  Cleanmgr finished with exit code: $($process.ExitCode)."
                }
            }
            catch {
                Write-Warning "  Failed to run cleanmgr.exe: $_"
            }

            return $totalFreed
        }

        $freedGB = [math]::Round($totalFreedBytes / 1GB, 2)
        Write-Host "--- [SET] Cleanup Summary ---" -ForegroundColor Green
        Write-Host "Total space freed by script: $freedGB GB (Additional space may have been cleared by cleanmgr.exe)"
        
        return $true # Signal to ImmyBot that the remediation step completed.
    }
}