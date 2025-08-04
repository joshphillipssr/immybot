function Test-C9EndpointSafeToReboot {
    <#
        .SYNOPSIS
            (Orchestrator) Determines if an endpoint is safe for invasive work, prioritizing explicit platform policies.
        .DESCRIPTION
            This is the definitive gatekeeper function. It performs a three-tiered safety check:
            1.  (Highest Priority) Checks an explicitly passed-in platform policy from a calling script.
            2.  (Second Priority) Checks for the global '$RebootPreference' variable from a Maintenance Task.
            3.  (Final Check) If no platform policy is found, it calls specialist functions like Get-C9UserIdleTime
                and Get-ComputerLockedStatus to perform granular checks.
        .PARAMETER PlatformPolicy
            An explicit policy string (e.g., "Suppress") passed from a calling script (e.g., an Install script).
        .PARAMETER InitialDelaySeconds
            An optional delay (in seconds) to apply before running checks, allowing system state to settle.
        .PARAMETER Computer
            The ImmyBot computer object to test. Defaults to the computer in the current context via (Get-ImmyComputer).
        .PARAMETER RequiredIdleMinutes
            The minimum number of minutes a user must be idle for the endpoint to be considered safe. Defaults to 30.
        .PARAMETER AllowWhenLocked
            A switch to indicate if a locked computer should be considered safe, regardless of idle time. Defaults to $true.
        .PARAMETER MaintenanceWindowStart
            The start time for a custom maintenance window in 24-hour format (e.g., "22:00"). This check runs IN ADDITION to the platform policy check.
        .PARAMETER MaintenanceWindowEnd
            The end time for a custom maintenance window in 24-hour format (e.g., "05:00").
        .PARAMETER IgnorePlatformPolicy
            A switch to bypass the primary check of the ImmyBot platform's '$RebootPreference' variable. Use with caution.
        .LOGMODULE
            Write-C9LogMessage should by imported into scripts that use this function
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$PlatformPolicy,

        [Parameter(Mandatory = $false)]
        [int]$InitialDelaySeconds = 5,

        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer),

        [Parameter(Mandatory = $false)]
        [int]$RequiredIdleMinutes = 30,

        [Parameter(Mandatory = $false)]
        [bool]$AllowWhenLocked = $true,

        [Parameter(Mandatory = $false)]
        [string]$MaintenanceWindowStart,

        [Parameter(Mandatory = $false)]
        [string]$MaintenanceWindowEnd,

        [Parameter(Mandatory = $false)]
        [switch]$IgnorePlatformPolicy

#        [Parameter(Mandatory = $false)]
#        [switch]$Quiet
    )

#    $VerbosePreference = 'Continue'

#    if ($Quiet) {
#    $VerbosePreference = 'SilentlyContinue'
#    }

$FunctionName = "Test-C9EndpointSafeToReboot"

    $result = [ordered]@{
        IsSafe          = $false
        Reason          = "Initial state."
        PlatformPolicy  = "Unknown"
        IdleTimeMinutes = -1
        LockStatus      = "Unknown"
        LoggedOnUser    = "Unknown"
        IsInMaintWindow = $false
    }

    try {
        if ($InitialDelaySeconds -gt 0) {
            Write-Host "[$ScriptName - $FunctionName] Applying initial settle-time delay of $InitialDelaySeconds second(s)..."
            Start-Sleep -Seconds $InitialDelaySeconds
        }
        
        $policySource = "None"
        $effectivePolicy = ""
        if (-not [string]::IsNullOrWhiteSpace($PlatformPolicy)) {
            $policySource = "Parameter"
            $effectivePolicy = $PlatformPolicy
        } elseif (Test-Path 'variable:global:RebootPreference') {
            $policySource = "Global Variable"
            $effectivePolicy = $global:RebootPreference
        }

        if ($policySource -ne "None") {
            $result.PlatformPolicy = $effectivePolicy
            Write-Host "[$ScriptName - $FunctionName] Detected platform policy via ${policySource}: RebootPreference = '$effectivePolicy'"
            
            if ($effectivePolicy -eq "Suppress" -and -not $IgnorePlatformPolicy.IsPresent) {
                $result.IsSafe = $false
                $result.Reason = "Action suppressed by platform policy (RebootPreference='Suppress')."
                return New-Object -TypeName PSObject -Property $result
            }
        } else {
            $result.PlatformPolicy = "Not Set"
            Write-Host "[$ScriptName - $FunctionName] No platform policy found. Proceeding with granular checks."
        }


        Write-Host "[$ScriptName - $FunctionName] Gathering granular endpoint status for $($Computer.Name)..."

        $idleTime = Get-C9UserIdleTime -Computer $Computer -ErrorAction Stop
        $lockStatus = Get-ComputerLockedStatus -Computer $Computer -ErrorAction Stop
        $result.IdleTimeMinutes = [int]$idleTime.TotalMinutes
        $result.LockStatus = $lockStatus
        
        Write-Host "[$ScriptName - $FunctionName] Endpoint idle for $($result.IdleTimeMinutes) minute(s). Lock status: $($result.LockStatus)."
       
        try {
            $loggedOnUsers = @(Get-LoggedOnUser -Computer $Computer -ErrorAction SilentlyContinue)
            if ($null -ne $loggedOnUsers) {
                $result.LoggedOnUser = $loggedOnUsers -join ', '
                Write-Host "[$ScriptName - $FunctionName] Found logged on user(s): $($result.LoggedOnUser)."
               
            } else {
                $result.LoggedOnUser = "None"
                Write-Host "[$ScriptName - $FunctionName] No interactive users found."
            }
        }
        catch {
            Write-Host "[$ScriptName - $FunctionName] Could not determine logged on user. $_"
            $result.LoggedOnUser = "Error"
        }
        
        $isWithinMaintenanceWindow = $false
        if (-not [string]::IsNullOrWhiteSpace($MaintenanceWindowStart) -and -not [string]::IsNullOrWhiteSpace($MaintenanceWindowEnd)) {
            Write-Host "[$ScriptName - $FunctionName] Checking custom maintenance window: $MaintenanceWindowStart - $MaintenanceWindowEnd"
            
            try {
                $endpointNow = Invoke-ImmyCommand -Computer $Computer -ScriptBlock { 
                    Write-Host "[$ScriptName - $FunctionName] Getting current time from endpoint..."
                    Get-Date 
                } -ErrorAction Stop
                
                $start = Get-Date -Date $endpointNow.Date -Hour ($MaintenanceWindowStart.Split(':')[0]) -Minute ($MaintenanceWindowStart.Split(':')[1])
                $end = Get-Date -Date $endpointNow.Date -Hour ($MaintenanceWindowEnd.Split(':')[0]) -Minute ($MaintenanceWindowEnd.Split(':')[1])

                if ($start -gt $end) { 
                    if (($endpointNow -ge $start) -or ($endpointNow -lt $end)) { 
                        $isWithinMaintenanceWindow = $true 
                    } 
                } else { 
                    if (($endpointNow -ge $start) -and ($endpointNow -lt $end)) { 
                        $isWithinMaintenanceWindow = $true 
                    } 
                }
                
                $result.IsInMaintWindow = $isWithinMaintenanceWindow
                Write-Host "[$ScriptName - $FunctionName] Endpoint current time: $($endpointNow.ToString('HH:mm')). Is within custom maintenance window: $isWithinMaintenanceWindow."
            }
            catch { 
                Write-Host "[$ScriptName - $FunctionName] Failed to check custom maintenance window: $_" 
            }
        }

        if ($result.LockStatus -eq 'LoggedOut' -or $idleTime -eq [TimeSpan]::MaxValue) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint is safe because no user is logged on."
        }
        elseif ($isWithinMaintenanceWindow) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint is safe because it is within the custom-defined maintenance window ($MaintenanceWindowStart - $MaintenanceWindowEnd)."
        }
        elseif ($result.LockStatus -eq 'Locked' -and $AllowWhenLocked) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint is safe because the screen is locked."
        }
        elseif ($result.IdleTimeMinutes -ge $RequiredIdleMinutes) {
            $result.IsSafe = $true
            $result.Reason = "Endpoint has been idle for $($result.IdleTimeMinutes) minutes, which meets the $($RequiredIdleMinutes)-minute requirement."
        }
        else {
            $result.IsSafe = $false
            $result.Reason = "User is active (Idle for $($result.IdleTimeMinutes) of $($RequiredIdleMinutes) mins) and endpoint is not locked or within a custom maintenance window."
        }

    } catch {
        $result.IsSafe = $false
        $result.Reason = "An error occurred while checking endpoint status: $($_.Exception.Message)"
        Write-Error $result.Reason
    }

    Write-Host "[$ScriptName - $FunctionName] Final Safety Check Result: $($result.IsSafe). Reason: $($result.Reason)"
    
    return New-Object -TypeName PSObject -Property $result
}