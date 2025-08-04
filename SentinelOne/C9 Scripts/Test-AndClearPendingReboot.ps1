function Test-AndClearPendingReboot {
    <#
    .SYNOPSIS
        Checks for pending reboots and automatically clears them if found.
    
    .DESCRIPTION
        This function checks if the system has a pending reboot and automatically 
        initiates a reboot to clear it. This prevents issues with software installations
        or other operations that might be blocked by pending reboots.
    
    .PARAMETER TimeoutDuration
        How long to wait for the reboot to complete. Default is 15 minutes.
    
    .PARAMETER LogPrefix
        Prefix for all log messages. Default is "[Test-AndClearPendingReboot]"
    
    .PARAMETER ThrowOnFailure
        If true, throws an exception on reboot failure. If false, returns false.
        Default is true.
    
    .EXAMPLE
        Test-AndClearPendingReboot
        
    .EXAMPLE
        Test-AndClearPendingReboot -TimeoutDuration (New-TimeSpan -Minutes 30) -LogPrefix "[MyScript]"
        
    .OUTPUTS
        Returns $true if no reboot was needed or reboot was successful.
        Returns $false if reboot was needed but failed (only when ThrowOnFailure is false).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [TimeSpan]$TimeoutDuration = (New-TimeSpan -Minutes 15),
        
        [Parameter()]
        [string]$LogPrefix = "[Test-AndClearPendingReboot]",
        
        [Parameter()]
        [bool]$ThrowOnFailure = $true
    )

    Write-Host "$LogPrefix Checking for pending reboot that could interfere with operations..."

    if (Test-PendingReboot) {
        Write-Warning "$LogPrefix A pending reboot has been detected. This must be cleared before proceeding."

        try {
            Write-Host "$LogPrefix Initiating reboot (timeout: $($TimeoutDuration.TotalMinutes) minutes)..."
            Restart-ComputerAndWait -TimeoutDuration $TimeoutDuration
            Write-Host "$LogPrefix ✓ Reboot completed successfully - system is ready."
            
        } catch {
            $ErrorMessage = "$LogPrefix Pending reboot could not be cleared. Error: $($_.Exception.Message)"
            
            if ($ThrowOnFailure) {
                throw $ErrorMessage
            } else {
                Write-Error $ErrorMessage
                return $false
            }
        }
    } else {
        Write-Host "$LogPrefix ✓ No pending reboot detected - system is ready."
    }

    Write-Host "$LogPrefix Pending reboot check complete."
    return $true
}