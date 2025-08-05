# =================================================================================
# Name:     C9MetascriptHelpers Module
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

function Invoke-C9EndpointCommand {
    <#
        .SYNOPSIS
            Executes a command-line process on an endpoint, capturing all output streams and the exit code.

        .DESCRIPTION
            A robust Metascript wrapper for Invoke-ImmyCommand that executes a specified executable on the target machine in the SYSTEM context.
        
            This function is designed to be a generic, reusable replacement for simple Invoke-ImmyCommand calls for executables. It provides three key advantages:
            1.  Reliably captures standard output (stdout), standard error (stderr), and the process exit code into a single, structured object.
            2.  Solves complex argument-passing issues by correctly handling arguments that contain spaces or quotes (e.g., passphrases, file paths).
            3.  Standardizes command execution and logging across all scripts.

        .PARAMETER FilePath
            The full path to the executable file on the target endpoint.

        .PARAMETER ArgumentList
            An array of strings representing the arguments to pass to the executable. 
            Each part of the command (the verb, switch, and value) should be a separate element in the array.
            The function will automatically handle quoting for arguments that contain spaces.
        
            For example, to run 'unprotect -k "my secret phrase"', the array should be:
            @('unprotect', '-k', 'my secret phrase')

        .PARAMETER WorkingDirectory
            The working directory from which to run the executable.

        .PARAMETER TimeoutSeconds
            The maximum number of seconds to wait for the command to complete. Defaults to 600 (10 minutes).

        .OUTPUTS
            A PSCustomObject containing the following properties:
            - ExitCode ([int]): The exit code returned by the process.
            - StandardOutput ([string]): The complete standard output from the process.
            - StandardError ([string]): The complete standard error from the process.

        .EXAMPLE
            # Example 1: Run a simple command with no arguments.
            $statusResult = Invoke-C9EndpointCommand -FilePath "C:\Program Files\S1\sentinelctl.exe" -ArgumentList "status"
        
            if ($statusResult.ExitCode -eq 0) {
                Write-Warning "[$ScriptName - $FunctionName] S1 Status: $($statusResult.StandardOutput)"
            }

        .EXAMPLE
            # Example 2: Run a command with a complex argument (e.g., a passphrase with spaces).
            $s1Path = "C:\Program Files\S1\sentinelctl.exe"
            $passphrase = "my secret pass phrase"
            $arguments = "unprotect", "-k", $passphrase

            $unprotectResult = Invoke-C9EndpointCommand -FilePath $s1Path -ArgumentList $arguments

            if ($unprotectResult.StandardError -and $unprotectResult.StandardError -notmatch "In-Process Client") {
                # Check for any real errors, ignoring known benign warnings.
                throw "An unexpected error occurred during unprotect: $($unprotectResult.StandardError)"
            } else {
                Write-Warning "[$ScriptName - $FunctionName] Unprotect command completed successfully."
            }

        .NOTES
            Author: Josh Phillips
            Date:   July 24, 2025

            Architectural Choice: Why `$using:` is used instead of `-ArgumentList`
            ---------------------------------------------------------------------
            Initial versions of this function attempted to pass parameters into the Invoke-ImmyCommand script block using the -ArgumentList parameter and a corresponding param() block.
        
            Extensive diagnostic testing proved this method to be unreliable within the ImmyBot platform for complex arguments. It resulted in a persistent parameter binding bug where arguments were scrambled upon arrival at the endpoint (e.g., the command 'status' was being bound to the FilePath parameter).
        
            The current implementation intentionally bypasses the -ArgumentList parameter. Instead, it uses the PowerShell `$using:` scope modifier (e.g., `$using:FilePath`) to directly and reliably inject variables from the parent Metascript into the endpoint's System context. This is the most direct, explicit, and robust method for passing data across the ImmyBot context boundary and aligns with the project's established architectural best practices.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath,

        [Parameter(Mandatory = $false, Position = 1)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 600,

        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Invoke-C9EndpointCommand"

    Write-Host "[$ScriptName - $FunctionName] Preparing to execute '$FilePath' with arguments: $($ArgumentList -join ' ')"

    # We use the $using: scope modifier to reliably pass variables into the script block,
    # bypassing the unreliable -ArgumentList parameter binding mechanism.
    $result = Invoke-ImmyCommand -Computer $Computer -Timeout $TimeoutSeconds -ScriptBlock {
        
        # We do not use a param() block here; we access the variables directly via $using:
        Write-Host "[$using:ScriptName - $using:FunctionName] Endpoint received command: '$($using:FilePath)'"
        Write-Host "[$using:ScriptName - $using:FunctionName] Endpoint received argument: '$($using:ArgumentList -join ' ')'"
        
        if (-not (Test-Path -Path $using:FilePath -PathType Leaf)) {
            throw "[$using:ScriptName - $using:FunctionName] Executable not found at path: $($using:FilePath)"
        }

        # This logic correctly handles arguments with spaces by quoting them.
        $formattedArgs = foreach ($arg in $using:ArgumentList) {
            if ($arg -match '\s') { "`"$arg`"" } else { $arg }
        }
        $argumentString = $formattedArgs -join ' '

        Write-Host "[$using:ScriptName - $using:FunctionName] Executing: `"$($using:FilePath)`" $argumentString"

        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $using:FilePath
        $pinfo.Arguments = $argumentString
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        if (-not [string]::IsNullOrWhiteSpace($using:WorkingDirectory)) {
            $pinfo.WorkingDirectory = $using:WorkingDirectory
        }
        
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo

        try {
            $p.Start() | Out-Null
            $p.WaitForExit()
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()
            return [PSCustomObject]@{ ExitCode = $p.ExitCode; StandardOutput = $stdout; StandardError = $stderr }
        }
        catch { throw "[$using:ScriptName - $using:FunctionName] Failed to start or monitor process '$($using:FilePath)'. Error: $_" }
        finally { if ($p) { $p.Dispose() } }

    } # Note: No -ArgumentList is used here.

    # Log the full results to the Metascript log for excellent visibility.
    if ($result) {
        Write-Host -ForegroundColor Green "[$ScriptName - $FunctionName] Command finished with Exit Code: $($result.ExitCode)."
        if (-not [string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            Write-Host -ForegroundColor Cyan "[$ScriptName - $FunctionName] --- Start Standard Output ---"
            Write-Host -ForegroundColor Green $result.StandardOutput
            Write-Host -ForegroundColor Cyan "[$ScriptName - $FunctionName] --- End Standard Output ---"
        }
        if (-not [string]::IsNullOrWhiteSpace($result.StandardError)) {
            Write-Warning "--- Start Standard Error ---"
            Write-Warning $result.StandardError
            Write-Warning "--- End Standard Error ---"
        }
    }

    return $result
}

function Test-C9IsUserLoggedIn {
    <#
    .SYNOPSIS
        (Helper) Determines if any interactive user is currently logged on to an endpoint.
    .DESCRIPTION
        This function performs a robust check to see if a user session is active. It uses the `quser.exe`
        command-line tool, which is reliable from the SYSTEM context, to check for sessions in an 'Active' state.
        This is more accurate than checking for 'explorer.exe' processes, which can linger in disconnected
        sessions.

        For diagnostic purposes, it also runs the original Get-LoggedOnUser check to allow for comparison.
    .PARAMETER Computer
        The ImmyBot computer object to test. Defaults to the computer in the current context via (Get-ImmyComputer).
    .OUTPUTS
        [bool] Returns $true if a user is in an 'Active' session, otherwise $false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Test-C9IsUserLoggedIn"
    Write-Host "[$ScriptName - $FunctionName] Starting logged-in user check on $($Computer.Name)..."

    # --- DIAGNOSTIC STEP 1: Get-LoggedOnUser has returned a false-positive a few times. Adding a diagnostic check and adding a quser verification leveraging the Invoke-C9EndpointCommand custom function ---
    try {
        $explorerUsers = @(Get-LoggedOnUser -Computer $Computer -ErrorAction SilentlyContinue)
        if ($null -ne $explorerUsers -and $explorerUsers.Count -gt 0) {
            Write-Host "[$ScriptName - $FunctionName] [DIAGNOSTIC] Get-LoggedOnUser (explorer.exe check) found user(s): $($explorerUsers -join ', ')." -ForegroundColor Yellow
        } else {
            Write-Host "[$ScriptName - $FunctionName] [DIAGNOSTIC] Get-LoggedOnUser (explorer.exe check) found no users." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "[$ScriptName - $FunctionName] [DIAGNOSTIC] Get-LoggedOnUser (explorer.exe check) failed: $_"
    }

    # --- DIAGNOSTIC STEP 2: Run the more reliable quser.exe check ---
    Write-Host "[$ScriptName - $FunctionName] Executing 'quser.exe' with 'Invoke-C9EndpointCommand' to get definitive session state..."
    try {
        
        $quserResult = Invoke-C9EndpointCommand -FilePath "quser.exe" -ArgumentList @() -Computer $Computer

        if ($quserResult.ExitCode -ne 0) {
            # quser.exe exits with code 1 if no users are logged on. This is expected.
            if (($quserResult.StandardOutput.Contains("no User exists for")) -or ($quserResult.StandardError.Contains("No User exists for"))) {
                Write-Host "[$ScriptName - $FunctionName] 'quser.exe' confirms no users are logged on. Returning `$false."
                return $false
            }
            else {
                Write-Warning "[$ScriptName - $FunctionName] 'quser.exe' failed with Exit Code $($quserResult.ExitCode) and an unexpected message. Assuming user is present for safety."
                Write-Warning "[$ScriptName - $FunctionName] Stderr: $($quserResult.StandardError)"
                Write-Warning "[$ScriptName - $FunctionName] Stdout: $($quserResult.StandardOutput)"
                return $true
            }
        }

        # Log the raw output for analysis
        # Write-Host "[$ScriptName - $FunctionName] --- Raw quser.exe Output ---"
        # Write-Host $quserResult.StandardOutput
        # Write-Host "--------------------------------"

        # Check the output for any line containing the word "Active"
        $isActiveSessionPresent = $quserResult.StandardOutput -match 'Active'

        if ($isActiveSessionPresent) {
            # For better logging, let's find which user is active
            $activeUserLine = ($quserResult.StandardOutput | Select-String 'Active').ToString()
            $activeUserName = ($activeUserLine.Trim() -split '\s+')[0]
            Write-Host "[$ScriptName - $FunctionName] 'quser.exe' confirms an ACTIVE session exists for user: $activeUserName. Returning `$true."
            return $true
        } else {
            Write-Host "[$ScriptName - $FunctionName] 'quser.exe' confirms no ACTIVE sessions were found (sessions may be disconnected). Returning `$false."
            return $false
        }
    }
    catch {
        Write-Warning "[$ScriptName - $FunctionName] An unexpected error occurred while running 'quser.exe'. Assuming user is present for safety. $_"
        return $true # Fail safe
    }
}

function Test-C9SystemPrerequisites {
    <#
    .SYNOPSIS
        Performs pre-flight checks on a system to ensure it is ready for a software change.
    .DESCRIPTION
        This Metascript function checks for common blocking conditions like a pending reboot or a locked MSI installer.
        It runs in ConstrainedLanguage mode and is safe for use in any Metascript context.
        It can optionally attempt to remediate a pending reboot. It returns a detailed status object.
    .PARAMETER AttemptRemediation
        If a pending reboot is detected, this switch will trigger a managed restart using Restart-ComputerAndWait.
    .PARAMETER RebootTimeout
        Specifies the timeout for the self-healing reboot operation. Defaults to 15 minutes.
    #>
    [CmdletBinding()]
    param(
        [switch]$AttemptRemediation,
        [timespan]$RebootTimeout = (New-TimeSpan -Minutes 15)
    )

    $FunctionName = "Test-C9SystemPrerequisites"

    Write-Warning "[$ScriptName - $FunctionName] Performing MSI and Pending Reboot checks..."

    # ConstrainedLanguage-Safe Object Creation
    $result = New-Object -TypeName PSObject
    Add-Member -InputObject $result -MemberType NoteProperty -Name 'MsiMutexLocked' -Value $false
    Add-Member -InputObject $result -MemberType NoteProperty -Name 'RebootPending' -Value $false
    Add-Member -InputObject $result -MemberType NoteProperty -Name 'RemediationAttempted' -Value $false
    Add-Member -InputObject $result -MemberType NoteProperty -Name 'RemediationSucceeded' -Value $false
    $messages = @()

    # --- Check 1: MSI Mutex ---
    Write-Warning "[$ScriptName - $FunctionName] Checking for active MSI installations..."
    try {
        Test-MsiExecMutex -ErrorAction Stop
        $messages += "[OK] No conflicting MSI installation is in progress."
    }
    catch {
        $result.MsiMutexLocked = $true
        $messages += "[FAIL] A conflicting MSI installation is in progress. Error: $($_.Exception.Message)"
    }

    # --- Check 2: Pending Reboot ---
    Write-Warning "[$ScriptName - $FunctionName] Checking for pending reboot state..."
    $rebootInfo = Test-PendingReboot
    
    # =========================================================================
    # --- BEGIN CORRECTED LOGIC ---
    # =========================================================================
    # The IsRebootPending property is what we must check.
    if ($rebootInfo.IsRebootPending) {
        $result.RebootPending = $true
        $messages += "[INFO] A pending reboot was detected."

        # Explicitly check if the -AttemptRemediation switch was used.
        if ($AttemptRemediation.IsPresent) {
            Write-Warning "[$ScriptName - $FunctionName] Attempting self-healing reboot as requested..."
            $result.RemediationAttempted = $true
            try {
                Restart-ComputerAndWait -TimeoutDuration $RebootTimeout
                # If Restart-ComputerAndWait succeeds, the script will halt here and resume after reboot.
                # The lines below will only run if the script continues for some reason.
                $result.RemediationSucceeded = $true
                $messages += "[SUCCESS] The self-healing reboot completed successfully."
            }
            catch {
                $result.RemediationSucceeded = $false
                $messages += "[FAIL] The self-healing reboot process failed. Last error: $($_.Exception.Message)"
            }
        }
    }
    else {
        $messages += "[OK] No pending reboot detected."
    }
    # =========================================================================
    # --- END CORRECTED LOGIC ---
    # =========================================================================

    # Add the final messages array to the result object
    Add-Member -InputObject $result -MemberType NoteProperty -Name 'Messages' -Value $messages

    Write-Warning "[$ScriptName - $FunctionName] Pre-flight checks complete."
    return $result
}

function Test-C9EndpointSafeToReboot {
    <#
        .SYNOPSIS
            (Orchestrator) Determines if an endpoint is safe for invasive work, prioritizing explicit platform policies.
        .DESCRIPTION
            This is the definitive gatekeeper function. It performs a three-tiered safety check:
            1.  (Highest Priority) Checks an explicitly passed-in platform policy from a calling script.
            2.  (Second Priority) Checks for the global '$rebootPreference' variable from a Maintenance Task.
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
            A switch to bypass the primary check of the ImmyBot platform's '$rebootPreference' variable. Use with caution.
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

    #    [Parameter(Mandatory = $false)]
    #    [switch]$Quiet
    )

    # $VerbosePreference = 'Continue'

    #if ($Quiet) {
    #$VerbosePreference = 'SilentlyContinue'
    #}

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
        } elseif (Test-Path 'variable:rebootPreference') {
            $policySource = "Global Variable"
            $effectivePolicy = $rebootPreference
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
        
 #       [Parameter()]
 #       [string]$LogPrefix = "Test-AndClearPendingReboot",
        
        [Parameter()]
        [bool]$ThrowOnFailure = $true
    )

    $FunctionName = "Test-AndClearPendingReboot"

    Write-Host "[$ScriptName - $FunctionName] Checking for pending reboot that could interfere with operations..."

    if (Test-PendingReboot) {
        Write-Warning "[$ScriptName - $FunctionName] A pending reboot has been detected. This must be cleared before proceeding."

        try {
            Write-Host "[$ScriptName - $FunctionName] Initiating reboot (timeout: $($TimeoutDuration.TotalMinutes) minutes)..."
            Restart-ComputerAndWait -TimeoutDuration $TimeoutDuration
            Write-Host "[$ScriptName - $FunctionName] ✓ Reboot completed successfully - system is ready."
            
        } catch {
            $ErrorMessage = "[$ScriptName - $FunctionName] Pending reboot could not be cleared. Error: $($_.Exception.Message)"
            
            if ($ThrowOnFailure) {
                throw $ErrorMessage
            } else {
                Write-Error [$ScriptName - $FunctionName] $ErrorMessage
                return $false
            }
        }
    } else {
        Write-Host "[$ScriptName - $FunctionName] ✓ No pending reboot detected - system is ready."
    }

    Write-Host "[$ScriptName - $FunctionName] Pending reboot check complete."
    return $true
}

function Get-C9UserIdleTime {
    <#
    .SYNOPSIS
        Gets the user idle time by executing a P/Invoke call within the interactive user's session.
    .DESCRIPTION
        This is the most accurate method for determining user idle time. It is called by the
        Test-C9EndpointSafeToReboot function.
    #>
    [CmdletBinding()]
    [OutputType([TimeSpan])]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )
    $FunctionName = "Get-C9UserIdleTime"

    Write-Host "[$ScriptName - $FunctionName] Getting idle time"
    $idleTimeSpan = try {
        # Execute in 'User' context to get accurate idle time from the interactive session.
        Invoke-ImmyCommand -Computer $Computer -Context User -ErrorAction Stop -ScriptBlock {
            # This P/Invoke C# code is self-contained and runs perfectly inside the user's session.
            Add-Type -TypeDefinition @"
            using System;
            using System.Diagnostics;
            using System.Runtime.InteropServices;
            namespace PInvoke.Win32 {
                public static class UserInput {
                    [DllImport("user32.dll", SetLastError=false)]
                    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
                    [StructLayout(LayoutKind.Sequential)]
                    private struct LASTINPUTINFO { public uint cbSize; public int dwTime; }
                    public static TimeSpan IdleTime {
                        get {
                            DateTime bootTime = DateTime.UtcNow.AddMilliseconds(-Environment.TickCount);
                            DateTime lastInput = bootTime.AddMilliseconds(LastInputTicks);
                            return DateTime.UtcNow.Subtract(lastInput);
                        }
                    }
                    public static int LastInputTicks {
                        get {
                            LASTINPUTINFO lii = new LASTINPUTINFO();
                            lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                            GetLastInputInfo(ref lii);
                            return lii.dwTime;
                        }
                    }
                }
            }
"@
            return [PInvoke.Win32.UserInput]::IdleTime
        }
    }
    catch {
        # If no user is logged on, this command fails, which is our signal the machine is idle.
        Write-Warning "[$ScriptName - $FunctionName] Could not execute in user context (likely no user is logged on). Assuming machine is idle."
        return [TimeSpan]::MaxValue
    }
    
    # We remove the Write-Host from the specialist function to reduce log noise. The orchestrator will log the final result.
    # Write-Warning "[$ScriptName - $FunctionName] Idle for $([int]($idleTimeSpan).TotalMinutes) minute(s)"
    Write-Host "[$ScriptName - $FunctionName] Idle time is $idleTimeSpan"
    return $idleTimeSpan
}



Export-ModuleMember -Function @(
    'Invoke-C9EndpointCommand',
    'Test-C9IsUserLoggedIn',
    'Test-C9SystemPrerequisites',
    'Test-C9EndpointSafeToReboot',
    'Test-AndClearPendingReboot',
    'Get-C9UserIdleTime'
)