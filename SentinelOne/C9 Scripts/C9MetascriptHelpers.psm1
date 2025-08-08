# =================================================================================
# Name:     C9MetascriptHelpers Module
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

function Get-C9ComputerLockedStatus {
    <#
    .SYNOPSIS
        Gets detailed computer lock status information by combining cached quser.exe results with reliable lock detection.
    .DESCRIPTION
        This function provides comprehensive computer lock status by first getting session information from the
        Get-C9QuserResult caching function, then determining the lock status using the proven LogonUI.exe process detection method.
    .OUTPUTS
        PSCustomObject with detailed lock status information.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer),
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeUserContextCheck
    )

    $FunctionName = "Get-C9ComputerLockedStatus"
    
    Write-Host "[$ScriptName - $FunctionName] Getting comprehensive computer lock status..."

    $result = [ordered]@{ # (result object initialization remains the same)
        HasActiveConsoleUser    = $false
        ConsoleUserName         = $null
        SessionState            = "Unknown"
        IsLocked                = $false
        LockStatus              = "Unknown"
        SystemContextLockStatus = "Unknown"
        UserContextLockStatus   = "Unknown"
        AllSessions             = @()
        ActiveSessions          = @()
        DisconnectedSessions    = @()
        SessionCount            = 0
        DataSource              = "quser.exe (cached) + tasklist.exe"
        RawQuserOutput          = ""
        LogonUIRunning          = $false
        DetectionMethod         = "System Context (tasklist)"
    }

    try {
        # Step 1: Use the new caching function to get reliable session information.
        Write-Host "[$ScriptName - $FunctionName] Getting user session information from Quser cache..."
        $quserResult = Get-C9QuserResult -Computer $Computer

        $result.RawQuserOutput = $quserResult.StandardOutput

        if ($quserResult.ExitCode -ne 0) {
            # quser.exe exits with code 1 if no users are logged on
            if (($quserResult.StandardOutput.Contains("no User exists for")) -or ($quserResult.StandardError.Contains("No User exists for"))) {
                Write-Host "[$ScriptName - $FunctionName] Cached quser data confirms no users are logged on"
                $result.LockStatus = "LoggedOut"
                $result.SystemContextLockStatus = "LoggedOut"
                return New-Object -TypeName PSObject -Property $result
            } else {
                Write-Warning "[$ScriptName - $FunctionName] Cached quser data indicates failure (Exit Code: $($quserResult.ExitCode))"
                $result.DataSource = "Error - quser failed"
                $result.LockStatus = "Unknown"
                return New-Object -TypeName PSObject -Property $result
            }
        }

        # Step 2: Parse quser output (This part of the logic is unchanged)
        Write-Host "[$ScriptName - $FunctionName] Parsing cached quser.exe output..."
        $sessions = @()
        $lines = $quserResult.StandardOutput -split "`r`n|`n" | Where-Object { $_.Trim() -ne "" }
        for ($i = 1; $i -lt $lines.Count; $i++) {
            # ... (the quser parsing logic is complex but remains exactly the same as before) ...
            $line = $lines[$i].Trim(); if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $parts = $line -split '\s+', 7; if ($parts.Count -ge 4) {
                $sessionProperties = [ordered]@{ UserName = $parts[0]; SessionName = if ($parts[1] -match '^\d+$') { "console"
            } else {
                $parts[1] }
                SessionId = if ($parts[1] -match '^\d+$') {
                    $parts[1]
                } else {
                    $parts[2] }
                    State = if ($parts[1] -match '^\d+$') {
                        $parts[2] } else { $parts[3] }
                        IdleTime = if ($parts[1] -match '^\d+$') {
                            $parts[3]
                        } else {
                            $parts[4] }
                            LogonTime = if ($parts[1] -match '^\d+$') {
                                ($parts[4..6] -join ' ')
                        } else {
                            ($parts[5..6] -join ' ')
                        }
                    }
                $session = New-Object -TypeName PSObject -Property $sessionProperties; $sessions += $session
                if ($session.State -eq "Active" -and ($session.SessionName -eq "console" -or $session.SessionId -match '^[0-2]$')) {
                    $result.HasActiveConsoleUser = $true
                    $result.ConsoleUserName = $session.UserName
                    $result.SessionState = $session.State
                    Write-Host "[$ScriptName - $FunctionName] Found active console user: $($session.UserName)"
                }
            }
        }
        $result.AllSessions = $sessions
        $result.ActiveSessions = @($sessions | Where-Object { $_.State -eq "Active" })
        $result.DisconnectedSessions = @($sessions | Where-Object { $_.State -eq "Disc" })
        $result.SessionCount = $sessions.Count
        Write-Host "[$ScriptName - $FunctionName] Found $($result.SessionCount) total sessions ($($result.ActiveSessions.Count) active, $($result.DisconnectedSessions.Count) disconnected)"

        # Step 3: System context lock detection using tasklist.exe (This is a different command and is unchanged)
        Write-Host "[$ScriptName - $FunctionName] Checking LogonUI.exe process for lock status using tasklist.exe..."
        $tasklistResult = Invoke-C9EndpointCommand -FilePath "tasklist.exe" -ArgumentList @("/FI", "IMAGENAME eq LogonUI.exe", "/FO", "CSV") -Computer $Computer
        # ... (The rest of the function for parsing tasklist and determining final lock status is unchanged) ...
        if ($tasklistResult.ExitCode -eq 0) {
            $result.LogonUIRunning = $tasklistResult.StandardOutput -match "LogonUI.exe"
            Write-Host "[$ScriptName - $FunctionName] tasklist.exe LogonUI detection result: $($result.LogonUIRunning)"
            if ($result.HasActiveConsoleUser) {
                if ($result.LogonUIRunning) {
                    $result.SystemContextLockStatus = "Locked"
                } else {
                    $result.SystemContextLockStatus = "Unlocked" }
            } else {
                $result.SystemContextLockStatus = "LoggedOut"
            }
        } else {
            Write-Warning "[$ScriptName - $FunctionName] Could not check LogonUI.exe process status"; $result.SystemContextLockStatus = "Error"
        }
        if ($IncludeUserContextCheck.IsPresent -and $result.HasActiveConsoleUser) {
            # ... (optional user context check unchanged) ...
        } else {
            if (-not $result.HasActiveConsoleUser) {
                $result.UserContextLockStatus = "No User"
            } else {
                $result.UserContextLockStatus = "Not Requested" } 
            }
        Write-Host "[$ScriptName - $FunctionName] Determining final lock status..."
        if (-not $result.HasActiveConsoleUser) {
            $result.LockStatus = "LoggedOut"
            $result.IsLocked = $false
        } else {
            if ($result.SystemContextLockStatus -eq "Locked") {
                $result.LockStatus = "Locked"
                $result.IsLocked = $true
            } elseif ($result.SystemContextLockStatus -eq "Unlocked") {
                $result.LockStatus = "Unlocked"
                $result.IsLocked = $false
            } else {
                if ($result.UserContextLockStatus -eq "Locked") {
                    $result.LockStatus = "Locked"
                    $result.IsLocked = $true
                } elseif ($result.UserContextLockStatus -eq "Unlocked") {
                    $result.LockStatus = "Unlocked"
                    $result.IsLocked = $false
                } else {
                    $result.LockStatus = "Unknown";
                    $result.IsLocked = $false
                }
            }
        }
        Write-Host "[$ScriptName - $FunctionName] Final lock status: $($result.LockStatus) (System: $($result.SystemContextLockStatus), User: $($result.UserContextLockStatus))"
    } catch {
        Write-Error "[$ScriptName - $FunctionName] Error gathering computer lock status: $($_.Exception.Message)"
        $result.DataSource = "Error"
        $result.LockStatus = "Error"
    }

    Write-Host "[$ScriptName - $FunctionName] computer lock status gathering complete"
    return New-Object -TypeName PSObject -Property $result
}

function Get-C9QuserResult {
    <#
    .SYNOPSIS
        (Internal Caching Helper) Gets the result of quser.exe, caching it in a script-scoped variable to avoid redundant calls.
    .DESCRIPTION
        This is a foundational performance optimization. It checks for a script-scoped variable '$script:quserResult'.
        If the variable is not populated, it executes 'quser.exe' via Invoke-C9EndpointCommand and stores the rich
        result object in the variable. Subsequent calls within the same script execution will return the cached result.
    .PARAMETER Computer
        The ImmyBot computer object.
    .OUTPUTS
        The rich PSCustomObject returned by Invoke-C9EndpointCommand for the quser.exe execution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Get-C9QuserResult"

    # Check if the result is already cached in the script's scope.
    if ($null -ne $script:quserResult) {
        Write-Host "[$ScriptName - $FunctionName] Returning cached quser.exe result."
        return $script:quserResult
    }

    # If not cached, execute the command and store the result.
    Write-Host "[$ScriptName - $FunctionName] No cached result found. Executing 'quser.exe' on endpoint..."
    try {
        # Store the result in the script: scope so it persists for this session.
        $script:quserResult = Invoke-C9EndpointCommand -FilePath "quser.exe" -ArgumentList @() -Computer $Computer
        Write-Host "[$ScriptName - $FunctionName] 'quser.exe' result has been cached."
        return $script:quserResult
    } catch {
        Write-Error "[$ScriptName - $FunctionName] A fatal error occurred while executing quser.exe. Error: $_"
        # --- THIS IS THE CORRECTED PART ---
        # On failure, cache a failure object so we don't retry repeatedly.
        # This ensures downstream functions receive a predictable object and don't crash.
        $script:quserResult = [PSCustomObject]@{
            ExitCode       = -1
            StandardError  = "Failed to execute quser.exe: $($_.Exception.Message)"
            StandardOutput = ""
        }
        return $script:quserResult
    }
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

    Write-Host "[$ScriptName - $FunctionName] Getting idle time via Invoke-ImmyCommand script block..."
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
    } catch {
        # If no user is logged on, this command fails, which is our signal the machine is idle.
        Write-Warning "[$ScriptName - $FunctionName] Could not execute in user context (likely no user is logged on). Assuming machine is idle."
        return [TimeSpan]::MaxValue
    }
    
    # We remove the Write-Host from the specialist function to reduce log noise. The orchestrator will log the final result.
    # Write-Warning "[$ScriptName - $FunctionName] Idle for $([int]($idleTimeSpan).TotalMinutes) minute(s)"
    Write-Host "[$ScriptName - $FunctionName] Idle time is $idleTimeSpan"
    return $idleTimeSpan
}

function Get-C9RebootPolicyContext {
    <#
    .SYNOPSIS
        Gets all available platform reboot policy variables and their current state.
    
    .DESCRIPTION
        This function consolidates all ImmyBot platform reboot policy variables into a single
        structured object. It checks for the availability and current values of all reboot-related
        variables that are passed into the metascript context by the platform.
        
        This is a foundational "Get" function that provides clean data collection for downstream
        decision logic functions.
    
    .PARAMETER Computer
        The ImmyBot computer object. Defaults to the computer in the current context via (Get-ImmyComputer).
        Included for consistency with other module functions, though policy variables are context-based.
    
    .EXAMPLE
        $policyContext = Get-C9RebootPolicyContext
        if ($policyContext.RebootPreference -eq "Suppress") {
            Write-Host "Platform policy is set to suppress reboots"
        }
    
    .OUTPUTS
        PSCustomObject with the following properties:
        - RebootPreference: Current reboot preference (Normal/Force/Suppress or $null if not set)
        - PromptTimeoutAction: Action when prompt times out (Reboot/Suppress/FailSession or $null)
        - AutoConsentToReboots: Whether to auto-consent to reboots ($true/$false or $null)
        - PromptTimeout: TimeSpan for prompt timeout duration (or $null)
        - IsRebootPreferenceAvailable: Boolean indicating if RebootPreference variable exists
        - IsPromptTimeoutActionAvailable: Boolean indicating if PromptTimeoutAction variable exists
        - IsAutoConsentToRebootsAvailable: Boolean indicating if AutoConsentToReboots variable exists
        - IsPromptTimeoutAvailable: Boolean indicating if PromptTimeout variable exists
        - PolicySource: String indicating source of policy detection
    #>
    
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Get-C9RebootPolicyContext"

    Write-Host "[$ScriptName - $FunctionName] Gathering platform reboot policy context..."

    # Initialize result object with all possible properties
    $result = [ordered]@{
        RebootPreference                   = $null
        PromptTimeoutAction                = $null
        AutoConsentToReboots               = $null
        PromptTimeout                      = $null
        IsRebootPreferenceAvailable        = $false
        IsPromptTimeoutActionAvailable     = $false
        IsAutoConsentToRebootsAvailable    = $false
        IsPromptTimeoutAvailable           = $false
        PolicySource                       = "None"
    }

    try {
        # Check for RebootPreference variable
        $rebootPrefVar = Get-Variable -Name 'RebootPreference' -ErrorAction SilentlyContinue
        if ($null -ne $rebootPrefVar) {
            $result.RebootPreference = $rebootPrefVar.Value
            $result.IsRebootPreferenceAvailable = $true
            $result.PolicySource = "Platform Variables"
            #Write-Host "[$ScriptName - $FunctionName] Found RebootPreference: '$($rebootPrefVar.Value)'"
        } else {
            Write-Host "[$ScriptName - $FunctionName] RebootPreference variable not found in current context"
        }

        # Check for PromptTimeoutAction variable
        $promptTimeoutActionVar = Get-Variable -Name 'promptTimeoutAction' -ErrorAction SilentlyContinue
        if ($null -ne $promptTimeoutActionVar) {
            $result.PromptTimeoutAction = $promptTimeoutActionVar.Value
            $result.IsPromptTimeoutActionAvailable = $true
            #Write-Host "[$ScriptName - $FunctionName] Found PromptTimeoutAction: '$($promptTimeoutActionVar.Value)'"
        } else {
            Write-Host "[$ScriptName - $FunctionName] PromptTimeoutAction variable not found in current context"
        }

        # Check for AutoConsentToReboots variable
        $autoConsentVar = Get-Variable -Name 'autoConsentToReboots' -ErrorAction SilentlyContinue
        if ($null -ne $autoConsentVar) {
            $result.AutoConsentToReboots = $autoConsentVar.Value
            $result.IsAutoConsentToRebootsAvailable = $true
            #Write-Host "[$ScriptName - $FunctionName] Found AutoConsentToReboots: '$($autoConsentVar.Value)'"
        } else {
            Write-Host "[$ScriptName - $FunctionName] AutoConsentToReboots variable not found in current context"
        }

        # Check for PromptTimeout variable
        $promptTimeoutVar = Get-Variable -Name 'promptTimeout' -ErrorAction SilentlyContinue
        if ($null -ne $promptTimeoutVar) {
            $result.PromptTimeout = $promptTimeoutVar.Value
            $result.IsPromptTimeoutAvailable = $true
            #Write-Host "[$ScriptName - $FunctionName] Found PromptTimeout: '$($promptTimeoutVar.Value)'"
        } else {
            Write-Host "[$ScriptName - $FunctionName] PromptTimeout variable not found in current context"
        }

        # Update PolicySource if any variables were found
        $availableCount = @(
            $result.IsRebootPreferenceAvailable,
            $result.IsPromptTimeoutActionAvailable,
            $result.IsAutoConsentToRebootsAvailable,
            $result.IsPromptTimeoutAvailable
        ) | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count

        if ($availableCount -gt 0) {
            Write-Host "[$ScriptName - $FunctionName] Found $availableCount platform reboot policy variable(s)"
        } else {
            Write-Host "[$ScriptName - $FunctionName] No platform reboot policy variables found in current context"
        }

    } catch {
        Write-Error "[$ScriptName - $FunctionName] Error gathering platform reboot policy context: $($_.Exception.Message)"
        $result.PolicySource = "Error"
    }

    $displayRows = Format-C9ObjectForDisplay -InputObject $result -DefaultCategory "Reboot Policy"

    # Format the collected rows into a table string and display it.
    $tableOutput = $displayRows | Format-Table -AutoSize | Out-String
    Write-Host "----------------- REBOOT POLICY CONTEXT -----------------"
    Write-Host -ForegroundColor Cyan $tableOutput
    Write-Host "---------------------------------------------------------"
    Write-Host "[$ScriptName - $FunctionName] Platform reboot policy context gathering complete."
    
    return New-Object -TypeName PSObject -Property $result
}

function Get-C9UserActivityStatus {
    <#
    .SYNOPSIS
        Gets comprehensive user activity information for an endpoint.
    
    .DESCRIPTION
        This function orchestrates calls to existing user activity functions to provide
        a complete picture of user activity status. It consolidates user login status,
        idle time, lock status, and session information into a single structured object.
        
        This is a foundational "Get" function that provides clean data collection for 
        downstream decision logic functions.
    
    .PARAMETER Computer
        The ImmyBot computer object. Defaults to the computer in the current context via (Get-ImmyComputer).
    
    .EXAMPLE
        $userActivity = Get-C9UserActivityStatus
        if ($userActivity.IsUserLoggedIn -and $userActivity.IdleTimeMinutes -lt 30) {
            Write-Host "User is active - not safe for maintenance"
        }
    
    .OUTPUTS
        PSCustomObject with the following properties:
        - IsUserLoggedIn: Boolean indicating if any user is in an active session
        - IdleTimeMinutes: Number of minutes the user has been idle (or -1 if no user)
        - IdleTimeSpan: Raw TimeSpan object from Get-C9UserIdleTime
        - LockStatus: Current lock status (Locked/Unlocked/LoggedOut/Unknown)
        - LoggedOnUsers: Array of logged on usernames (from Get-LoggedOnUser)
        - LoggedOnUsersCount: Count of logged on users
        - SessionInfo: Summary string describing the current session state
        - DataSource: Source of the activity detection
    #>
    
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Get-C9UserActivityStatus"
    
    Write-Host "[$ScriptName - $FunctionName] Gathering comprehensive user activity status..."

    # Initialize result object
    $result = [ordered]@{
        IsUserLoggedIn      = $false
        IdleTimeMinutes     = -1
        IdleTimeSpan        = $null
        LockStatus          = "Unknown"
        LoggedOnUsers       = @()
        LoggedOnUsersCount  = 0
        SessionInfo         = "Unknown"
        DataSource          = "Multiple Sources"
    }

    try {
        # Step 1: Check if user is logged in (using existing function)
        Write-Host "[$ScriptName - $FunctionName] Checking user login status via Test-C9IsUserLoggedIn..."
        $result.IsUserLoggedIn = Test-C9IsUserLoggedIn -Computer $Computer
        
        # Step 2: Get idle time (using existing function)
        Write-Host "[$ScriptName - $FunctionName] Checking user idle time via Get-C9UserIdleTime..."
        $idleTimeSpan = Get-C9UserIdleTime -Computer $Computer
        $result.IdleTimeSpan = $idleTimeSpan
        
        if ($idleTimeSpan -eq [TimeSpan]::MaxValue) {
            $result.IdleTimeMinutes = -1
            $result.SessionInfo = "No user logged on"
        } else {
            $result.IdleTimeMinutes = [int]$idleTimeSpan.TotalMinutes
        }

        # Step 3: Get lock status (using existing ImmyBot function)
        Write-Host "[$ScriptName - $FunctionName] Checking computer lock status via Get-C9ComputerLockedStatus..."
        try {
            $computerLockStatus = Get-C9ComputerLockedStatus -Computer $Computer -ErrorAction Stop
            $result.LockStatus = $computerLockStatus.LockStatus
            Write-Host -ForegroundColor Green "[$ScriptName - $FunctionName] Current lock status: $($result.LockStatus)"
        } catch {
            Write-Warning "[$ScriptName - $FunctionName] Could not determine lock status: $_"
            $result.LockStatus = "Error"
        }

        # Step 4: Get logged on users (using existing ImmyBot function for completeness)
        Write-Host "[$ScriptName - $FunctionName] Getting logged on users list via Get-LoggedOnUser..."
        try {
            $loggedOnUsers = @(Get-LoggedOnUser -Computer $Computer -ErrorAction SilentlyContinue)
            if ($null -ne $loggedOnUsers -and $loggedOnUsers.Count -gt 0) {
                $result.LoggedOnUsers = $loggedOnUsers
                $result.LoggedOnUsersCount = $loggedOnUsers.Count
            } else {
                $result.LoggedOnUsers = @()
                $result.LoggedOnUsersCount = 0
            }
        } catch {
            Write-Warning "[$ScriptName - $FunctionName] Could not get logged on users: $_"
            $result.LoggedOnUsers = @()
            $result.LoggedOnUsersCount = 0
        }

        # Step 5: Build session info summary
        if (-not $result.IsUserLoggedIn) {
            $result.SessionInfo = "No active user sessions"
        } elseif ($result.LockStatus -eq "Locked") {
            $result.SessionInfo = "User logged in but screen is locked (idle: $($result.IdleTimeMinutes) min)"
        } elseif ($result.IdleTimeMinutes -ge 0) {
            $result.SessionInfo = "User active session (idle: $($result.IdleTimeMinutes) min, lock: $($result.LockStatus))"
        } else {
            $result.SessionInfo = "User session detected but idle time unknown"
        }

        Write-Host "[$ScriptName - $FunctionName] User activity summary: $($result.SessionInfo)"

    } catch {
        Write-Error "[$ScriptName - $FunctionName] Error gathering user activity status: $($_.Exception.Message)"
        $result.SessionInfo = "Error occurred during status check"
        $result.DataSource = "Error"
    }

    Write-Host "[$ScriptName - $FunctionName] User activity status gathering complete"
    
    return New-Object -TypeName PSObject -Property $result
}

function Get-C9SystemRebootRequirements {
    <#
    .SYNOPSIS
        Gets comprehensive system reboot requirement information for an endpoint.
    
    .DESCRIPTION
        This function orchestrates calls to the native Test-PendingReboot function to provide
        a complete picture of system reboot requirements. It categorizes different types of
        pending reboots and provides structured data for downstream decision logic functions.
        
        This is a foundational "Get" function that provides clean data collection for 
        downstream decision logic functions.
    
    .PARAMETER Computer
        The ImmyBot computer object. Defaults to the computer in the current context via (Get-ImmyComputer).
    
    .EXAMPLE
        $rebootRequirements = Get-C9SystemRebootRequirements
        if ($rebootRequirements.IsRebootPending -and $rebootRequirements.HasCriticalRebootSources) {
            Write-Host "Critical reboot required - cannot proceed with software changes"
        }
    
    .OUTPUTS
        PSCustomObject with the following properties:
        - IsRebootPending: Boolean indicating if any reboot is pending
        - HasCriticalRebootSources: Boolean indicating if critical OS-level reboots are pending
        - RebootSources: Array of strings describing what is causing reboot requirements
        - CriticalSources: Array of critical reboot sources that should not be ignored
        - NonCriticalSources: Array of non-critical reboot sources
        - WindowsUpdateRelated: Boolean indicating if Windows Update is involved
        - ComponentBasedServicing: Boolean from native Test-PendingReboot
        - PendingComputerRenameDomainJoin: Boolean from native Test-PendingReboot
        - PendingFileRenameOperations: Boolean from native Test-PendingReboot
        - SystemCenterConfigManager: Boolean from native Test-PendingReboot
        - WindowsUpdateAutoUpdate: Boolean from native Test-PendingReboot
        - PendingRebootStartTime: DateTime from native Test-PendingReboot
        - RawPendingRebootData: Full detailed output from Test-PendingReboot
        - DataSource: Source of the reboot detection
    #>
    
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Get-C9SystemRebootRequirements"
    
    Write-Host "[$ScriptName - $FunctionName] Gathering system reboot requirements..."

    # Initialize result object with only core types
    $result = [ordered]@{
        IsRebootPending      = $false
        RebootWillBeRequired = $false # Formerly HasCriticalRebootSources
        ReasonsForReboot     = @()   # Formerly RebootSources
        CriticalSources      = @()
        NonCriticalSources   = @()
        WindowsUpdateRelated = $false
        DataSource           = "Native Test-PendingReboot"
    }

    try {
        # Step 1: Get detailed pending reboot information using native function
        Write-Host "[$ScriptName - $FunctionName] Checking for pending reboot conditions..."
        
        # The -Passthru returns a complex object that we must NOT return directly.
        $pendingRebootData = Test-PendingReboot -Computer $Computer -Passthru
        
        if ($null -eq $pendingRebootData) {
            Write-Warning "[$ScriptName - $FunctionName] Test-PendingReboot returned null data"
            $result.DataSource = "Error - No Data"
            return New-Object -TypeName PSObject -Property $result
        }

        # Step 2: Extract ONLY the primitive values from the complex object
        $result.IsRebootPending = $pendingRebootData.IsRebootPending
        $isComponentBasedServicing = $pendingRebootData.ComponentBasedServicing
        $isPendingComputerRenameDomainJoin = $pendingRebootData.PendingComputerRenameDomainJoin
        $isWindowsUpdateAutoUpdate = $pendingRebootData.WindowsUpdateAutoUpdate
        $isPendingFileRenameOperations = $pendingRebootData.PendingFileRenameOperations
        $isSystemCenterConfigManager = $pendingRebootData.SystemCenterConfigManager
        $pendingRebootStartTime = $pendingRebootData.PendingRebootStartTime

        Write-Host "[$ScriptName - $FunctionName] Overall reboot pending status: $($result.IsRebootPending)"

        # Step 3: Categorize reboot sources
        if ($result.IsRebootPending) {
            Write-Host "[$ScriptName - $FunctionName] Analyzing reboot sources..."

            if ($isComponentBasedServicing) {
                $result.CriticalSources += "Component Based Servicing"
                $result.RebootSources += "Component Based Servicing (OS components changed)"
            }
            if ($isPendingComputerRenameDomainJoin) {
                $result.CriticalSources += "Computer Rename/Domain Join"
                $result.RebootSources += "Computer Rename or Domain Join operation"
            }
            if ($isWindowsUpdateAutoUpdate) {
                $result.CriticalSources += "Windows Update Auto Update"
                $result.RebootSources += "Windows Update Auto Update"
                $result.WindowsUpdateRelated = $true
            }
            if ($isPendingFileRenameOperations) {
                $result.NonCriticalSources += "Pending File Rename Operations"
                $result.RebootSources += "Pending File Rename Operations"
            }
            if ($isSystemCenterConfigManager) {
                $result.NonCriticalSources += "System Center Configuration Manager"
                $result.RebootSources += "System Center Configuration Manager"
            }

            if ($null -ne $pendingRebootStartTime -and -not [string]::IsNullOrWhiteSpace($pendingRebootStartTime)) {
                try {
                    $rebootTime = [datetime]$pendingRebootStartTime
                    if ($rebootTime -gt (Get-Date).ToUniversalTime()) {
                        $result.CriticalSources += "Windows Update Orchestrator"
                        $result.RebootSources += "Windows Update Orchestrator (scheduled reboot)"
                        $result.WindowsUpdateRelated = $true
                    }
                } catch {
                    Write-Warning "[$ScriptName - $FunctionName] Could not parse PendingRebootStartTime: $pendingRebootStartTime"
                }
            }

            $result.RebootWillBeRequired = $result.CriticalSources.Count -gt 0
        } else {
            Write-Host "[$ScriptName - $FunctionName] No pending reboot detected"
        }

    } catch {
        Write-Error "[$ScriptName - $FunctionName] Error gathering system reboot requirements: $($_.Exception.Message)"
        $result.DataSource = "Error"
        $result.RebootSources = @("Error occurred during detection")
    }

    Write-Host "[$ScriptName - $FunctionName] System reboot requirements gathering complete"
    
    # Return the new, "flat" object that is ConstrainedLanguage-safe
    return New-Object -TypeName PSObject -Property $result
}

function Test-C9IsUserLoggedIn {
    <#
    .SYNOPSIS
        (Helper) Determines if any interactive user is currently logged on to an endpoint.
    .DESCRIPTION
        This function performs a robust check to see if a user session is active. It now uses the
        Get-C9QuserResult caching function to get session data, which is more efficient.
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

    try {
        # --- REFACTORED LOGIC ---
        # Get the cached or live result from our new helper function. This is the only change.
        $quserResult = Get-C9QuserResult -Computer $Computer

        # The rest of the parsing logic is the same, but it now operates on cached data.
        if ($quserResult.ExitCode -ne 0) {
            # quser.exe exits with code 1 if no users are logged on. This is expected.
            if (($quserResult.StandardOutput.Contains("no User exists for")) -or ($quserResult.StandardError.Contains("No User exists for"))) {
                Write-Host "[$ScriptName - $FunctionName] quser data confirms no users are logged on. Returning `$false."
                return $false
            } else {
                Write-Warning "[$ScriptName - $FunctionName] quser data indicates failure with Exit Code $($quserResult.ExitCode). Assuming user is present for safety."
                return $true
            }
        }

        # Check the output for any line containing the word "Active"
        $isActiveSessionPresent = $quserResult.StandardOutput -match 'Active'

        if ($isActiveSessionPresent) {
            $outputLines = $quserResult.StandardOutput -split '(?:\r\n|\r|\n)'
            $activeUserLine = $null
            for ($i = 1; $i -lt $outputLines.Length; $i++) {
                if ($outputLines[$i] -match '\bActive\b') {
                    $activeUserLine = $outputLines[$i]; break
                }
            }
    
            if ($activeUserLine) {
                $activeUserName = ($activeUserLine.Trim() -split '\s+')[0]
                Write-Host "[$ScriptName - $FunctionName] quser data confirms an ACTIVE session exists for user: $activeUserName. Returning `$true."
            } else {
                Write-Host "[$ScriptName - $FunctionName] quser data shows Active session but could not parse username. Returning `$true."
            }
            return $true
        } else {
            Write-Host "[$ScriptName - $FunctionName] quser data confirms no ACTIVE sessions were found (sessions may be disconnected). Returning `$false."
            return $false
        }
    } catch {
        Write-Warning "[$ScriptName - $FunctionName] An unexpected error occurred while analyzing quser data. Assuming user is present for safety. $_"
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
        Test-C9MsiExecMutex -ErrorAction Stop
        $messages += "[OK] No conflicting MSI installation is in progress."
    } catch {
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
            } catch {
                $result.RemediationSucceeded = $false
                $messages += "[FAIL] The self-healing reboot process failed. Last error: $($_.Exception.Message)"
            }
        }
    } else {
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
        $computerLockStatus = Get-C9ComputerLockedStatus -Computer $Computer -ErrorAction Stop
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
        } catch {
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
            } catch { 
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

function Test-C9RebootDecision {
    <#
    .SYNOPSIS
        Orchestrates comprehensive reboot decision logic for software package operations.
    
    .DESCRIPTION
        This function implements decision logic for three key reboot scenarios by orchestrating
        calls to all foundational Get functions. It respects platform policies while applying
        software-specific overrides for critical operations that cannot be left in pending states.
        
        This is the primary "Test" function that provides decision logic for downstream
        action functions.
    
    .PARAMETER Scenario
        The reboot scenario being evaluated:
        - PreAction: Check before making changes that may require reboot
        - PostAction: Decide whether to reboot after changes requiring reboot  
        - ClearPending: Decide whether to clear existing pending reboot before proceeding
    
    .PARAMETER SystemState
        A pre-gathered PSCustomObject containing system state information. If provided, the function
        will skip live data gathering and use this object's data, significantly improving efficiency.
        The object should contain .RebootPolicy, .UserActivity, and .RebootRequirements properties.

    .PARAMETER MaxUserIdleMinutes
        Maximum minutes a user can be idle before considering the endpoint safe for reboot.
        Defaults to 120 minutes (2 hours).
    
    .PARAMETER PromptTimeoutMinutes
        Minutes to wait for user response when prompting about reboot.
        Defaults to 5 minutes.
    
    .PARAMETER AllowUserCancel
        Whether to allow user to cancel the reboot operation.
        - $true: User can cancel (for PreAction/ClearPending scenarios)
        - $false: User gets notification but cannot cancel (for PostAction scenario)
        Defaults to $true.
    
    .PARAMETER OverrideSuppression
        Whether to override platform 'Suppress' policy for critical operations.
        Use this for operations that cannot be left in pending states.
        Defaults to $false.
    
    .PARAMETER WhatIf
        If specified, runs all decision logic but does not perform any actual reboots.
        Shows what actions would be taken for testing and troubleshooting purposes.
        Defaults to $false.
    
    .PARAMETER Computer
        The ImmyBot computer object. Defaults to the computer in the current context via (Get-ImmyComputer).
    
    .EXAMPLE
        # Pre-action check before S1 installation
        $decision = Test-C9RebootDecision -Scenario PreAction -OverrideSuppression $true
        if (-not $decision.ShouldProceed) {
            throw "Cannot proceed with installation: $($decision.Reason)"
        }
    
    .EXAMPLE
        # Post-action check after S1 installation requiring reboot
        $decision = Test-C9RebootDecision -Scenario PostAction -AllowUserCancel $false
        if ($decision.ShouldReboot) {
            Write-Host "Proceeding with required reboot: $($decision.Reason)"
        }
    
    .EXAMPLE
        # Test what would happen without actually rebooting
        $decision = Test-C9RebootDecision -Scenario PostAction -WhatIf
        Write-Host "Would reboot: $($decision.ShouldReboot), Reason: $($decision.Reason)"
    
    .OUTPUTS
        PSCustomObject with the following properties:
        - ShouldProceed: Boolean indicating whether the operation should proceed
        - ShouldReboot: Boolean indicating whether a reboot should be performed
        - ShouldPromptUser: Boolean indicating whether user interaction is recommended
        - UserInteractionMode: String describing the type of user interaction (None/Prompt/Notify)
        - Reason: String explaining the decision
        - PlatformPolicy: Current platform reboot preference
        - UserActivitySummary: Summary of current user activity
        - RebootRequirementsSummary: Summary of pending reboot requirements
        - OverrideApplied: Boolean indicating if platform policy was overridden
        - RecommendedAction: String describing the recommended next action
        - WhatIfMode: Boolean indicating if this was a test run
        - RawData: Object containing all raw data from Get functions
    #>
    
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PreAction', 'PostAction', 'ClearPending')]
        [string]$Scenario,
        
        # --- NEW PARAMETER ---
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$SystemState,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxUserIdleMinutes = 120,
        
        [Parameter(Mandatory = $false)]
        [int]$PromptTimeoutMinutes = 5,
        
        [Parameter(Mandatory = $false)]
        [bool]$AllowUserCancel = $true,
        
        [Parameter(Mandatory = $false)]
        [bool]$OverrideSuppression = $false,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf,
        
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Test-C9RebootDecision"
    
    Write-Host "[$ScriptName - $FunctionName] Starting reboot decision analysis for scenario: $Scenario$(if ($WhatIf) { ' (WhatIf Mode)' })"

    # Initialize result object
    $result = [ordered]@{
        ShouldProceed               = $false
        ShouldReboot                = $false
        ShouldPromptUser            = $false
        UserInteractionMode         = "None"
        Reason                      = "Initial state"
        PlatformPolicy              = "Unknown"
        UserActivitySummary         = "Unknown"
        RebootRequirementsSummary   = "Unknown"
        OverrideApplied             = $false
        RecommendedAction           = "None"
        WhatIfMode                  = $WhatIf.IsPresent
        RawData                     = @{}
    }

    try {
        # --- MODIFIED LOGIC: Use pre-gathered state if provided, otherwise gather live data ---
        if ($null -ne $SystemState) {
            Write-Host "[$ScriptName - $FunctionName] Using pre-gathered system state object."
            $policyContext = $SystemState.RebootPolicy
            $userActivity = $SystemState.UserActivity
            $rebootRequirements = $SystemState.RebootRequirements
        } else {
            # --- FALLBACK: Gather data now if no state object was passed ---
            Write-Host "[$ScriptName - $FunctionName] No system state object provided. Gathering live data now..."
            $policyContext = Get-C9RebootPolicyContext -Computer $Computer
            $userActivity = Get-C9UserActivityStatus -Computer $Computer
            $rebootRequirements = Get-C9SystemRebootRequirements -Computer $Computer
        }

        # Store raw data for advanced use cases
        $result.RawData = @{
            PolicyContext      = $policyContext
            UserActivity       = $userActivity
            RebootRequirements = $rebootRequirements
        }

        # Extract key information for decision logic
        $result.PlatformPolicy = $policyContext.RebootPreference
        $result.UserActivitySummary = $userActivity.SessionInfo
        $result.RebootRequirementsSummary = if ($rebootRequirements.IsRebootPending) {
            "Pending: $($rebootRequirements.RebootSources -join ', ')"
        } else {
            "No pending reboot detected"
        }

        Write-Host "[$ScriptName - $FunctionName] Current platform reboot policy: $($result.PlatformPolicy)"
        Write-Host "[$ScriptName - $FunctionName] Current user activity: $($result.UserActivitySummary)"
        Write-Host "[$ScriptName - $FunctionName] Current reboot requirements: $($result.RebootRequirementsSummary)"
        Write-Host "[$ScriptName - $FunctionName] Proceeding to decision logic for scenario: $Scenario"

        # Step 2: Apply scenario-specific decision logic (this part remains unchanged)
        switch ($Scenario) {
            'PreAction' {
                $result = Invoke-PreActionDecisionLogic -Result $result -PolicyContext $policyContext -UserActivity $userActivity -RebootRequirements $rebootRequirements -MaxUserIdleMinutes $MaxUserIdleMinutes -OverrideSuppression $OverrideSuppression -AllowUserCancel $AllowUserCancel -PromptTimeoutMinutes $PromptTimeoutMinutes -WhatIf $WhatIf.IsPresent -Computer $Computer
            }
            'PostAction' {
                $result = Invoke-PostActionDecisionLogic -Result $result -PolicyContext $policyContext -UserActivity $userActivity -RebootRequirements $rebootRequirements -MaxUserIdleMinutes $MaxUserIdleMinutes -AllowUserCancel $AllowUserCancel -PromptTimeoutMinutes $PromptTimeoutMinutes -WhatIf $WhatIf.IsPresent -Computer $Computer
            }
            'ClearPending' {
                $result = Invoke-ClearPendingDecisionLogic -Result $result -PolicyContext $policyContext -UserActivity $userActivity -RebootRequirements $rebootRequirements -MaxUserIdleMinutes $MaxUserIdleMinutes -OverrideSuppression $OverrideSuppression -AllowUserCancel $AllowUserCancel -PromptTimeoutMinutes $PromptTimeoutMinutes -WhatIf $WhatIf.IsPresent -Computer $Computer
            }
        }

    } catch {
        Write-Error "[$ScriptName - $FunctionName] Error during reboot decision analysis: $($_.Exception.Message)"
        $result.Reason = "Error occurred during decision analysis: $($_.Exception.Message)"
        $result.RecommendedAction = "Review error and retry"
    }

    Write-Host "[$ScriptName - $FunctionName] Decision complete. Should proceed: $($result.ShouldProceed), Should reboot: $($result.ShouldReboot)"
    Write-Host "[$ScriptName - $FunctionName] Reason: $($result.Reason)"
    
    return New-Object -TypeName PSObject -Property $result
}

function Test-UserActivityForReboot {
    <#
    .SYNOPSIS
        Evaluates user activity to determine if a reboot is safe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $UserActivity,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxUserIdleMinutes
    )

    $result = @{
        IsSafe = $false
        ShouldPrompt = $false
        Reason = "Unknown"
    }

    # No user logged in - always safe
    if (-not $UserActivity.IsUserLoggedIn) {
        $result.IsSafe = $true
        $result.Reason = "No user is logged in - safe to reboot"
        return $result
    }
    
    # User is logged in but screen is locked - generally safe
    if ($UserActivity.LockStatus -eq "Locked") {
        $result.IsSafe = $true
        $result.Reason = "User is logged in but screen is locked - safe to reboot"
        return $result
    }
    
    # User is logged in and screen is unlocked - check idle time
    if ($UserActivity.IdleTimeMinutes -ge $MaxUserIdleMinutes) {
        $result.IsSafe = $true
        $result.Reason = "User has been idle for $($UserActivity.IdleTimeMinutes) minutes (threshold: $MaxUserIdleMinutes) - safe to reboot"
        return $result
    }
    
    # User is active - not safe but should prompt if idle time is reasonable
    if ($UserActivity.IdleTimeMinutes -ge 30) {  # At least 30 minutes idle
        $result.IsSafe = $false
        $result.ShouldPrompt = $true
        $result.Reason = "User is active (idle: $($UserActivity.IdleTimeMinutes) min) but may accept reboot prompt"
        return $result
    }
    
    # User is very active - not safe and shouldn't prompt
    $result.IsSafe = $false
    $result.ShouldPrompt = $false
    $result.Reason = "User is very active (idle: $($UserActivity.IdleTimeMinutes) min) - not safe to reboot"
    return $result
}

function Test-C9MsiExecMutex {
    <#
    .SYNOPSIS
        (Metascript Orchestrator) A robust, ConstrainedLanguage-safe function to check if the MSI installer mutex is locked.
    .DESCRIPTION
        This is a custom, hardened replacement for the built-in Test-MsiExecMutex.
        It uses Invoke-ImmyCommand to run advanced C# and WMI logic on the endpoint in the FullLanguage context.
        Crucially, it is designed to prevent complex .NET objects (like Win32_Process) from "leaking" back to the
        Metascript, which would cause a "Cannot create type" error.
        It returns a simple, clean PSCustomObject that is safe to use in any Metascript.
    .PARAMETER MsiExecWaitTime
        The maximum duration to wait for the mutex to become free. Defaults to 60 seconds.
    .PARAMETER Computer
        The target computer object. Defaults to the computer in the current context via (Get-ImmyComputer).
    .OUTPUTS
        On success, this function does not output anything to the success stream but returns $true.
        On failure (if the mutex is locked), it throws a terminating error with a detailed reason.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [timespan]$MsiExecWaitTime = $(New-TimeSpan -Seconds 60),

        [Parameter(Mandatory=$false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Test-C9MsiExecMutex"
    Write-Host "[$ScriptName - $FunctionName] Checking MSI mutex availability..."

    # The entire check is performed on the endpoint, which returns a simple, safe object.
    $resultObject = Invoke-ImmyCommand -Computer $Computer -Timeout 300 {
        
        # --- Start of Endpoint Logic (System Context / FullLanguage) ---

        # We access Metascript variables using the reliable $using: scope modifier.
        $localWaitTime = $using:MsiExecWaitTime

        # Define the C# helper class. This is safe in the FullLanguage endpoint context.
        # This is a more robust version than the original, handling more exceptions.
        $IsMsiExecFreeSource = @'
        using System;
        using System.Threading;
        public class MsiExec {
            public static bool IsMsiExecFree(TimeSpan maxWaitTime) {
                const string mutexName = "Global\\_MSIExecute";
                Mutex msiMutex = null;
                bool isMutexFree = false;
                try {
                    msiMutex = Mutex.OpenExisting(mutexName, System.Security.AccessControl.MutexRights.Synchronize);
                    isMutexFree = msiMutex.WaitOne(maxWaitTime, false);
                }
                catch (WaitHandleCannotBeOpenedException) { isMutexFree = true; } // Mutex doesn't exist, so it's free.
                catch (ObjectDisposedException) { isMutexFree = true; } // Mutex was disposed, so it's free.
                finally { if (msiMutex != null && isMutexFree) { msiMutex.ReleaseMutex(); msiMutex.Dispose(); } }
                return isMutexFree;
            }
        }
'@
        if (-not ([System.Management.Automation.PSTypeName]'MsiExec').Type) {
            Add-Type -TypeDefinition $IsMsiExecFreeSource -Language CSharp -ErrorAction 'Stop'
        }

        # Initialize a clean result object to be returned to the Metascript.
        $endpointResult = [PSCustomObject]@{
            IsLocked = $true # Assume locked until proven otherwise
            Reason   = "Initial state"
        }

        # Check the mutex.
        if ([MsiExec]::IsMsiExecFree($localWaitTime)) {
            $endpointResult.IsLocked = $false
            $endpointResult.Reason = "Mutex [Global\\_MSIExecute] is available."
        } else {
            # --- THE BUG FIX IS HERE ---
            # We explicitly cast the assignment to [void] to prevent the complex WMI objects
            # from "leaking" onto the success output stream. This stops the ConstrainedLanguage error.
            [void]($msiProcesses = Get-WmiObject -Class Win32_Process -Filter "name = 'msiexec.exe'")
            
            $conflictingCommands = $msiProcesses | ForEach-Object { $_.CommandLine.Trim() }

            $endpointResult.IsLocked = $true
            $endpointResult.Reason = "Mutex [Global\\_MSIExecute] is locked. Conflicting processes: $($conflictingCommands -join '; ')"
        }
        
        # Return the clean, simple object. This is all the Metascript will see.
        return $endpointResult
        # --- End of Endpoint Logic ---
    }

    # The outer Metascript function now inspects the clean object and takes action.
    if ($resultObject.IsLocked) {
        # If locked, we throw a clean, informative error. This is the correct behavior for a "Test" function.
        throw "Pre-flight check failed: $($resultObject.Reason)"
    } else {
        # If not locked, we log the success and simply return, allowing the script to continue.
        Write-Host "[$ScriptName - $FunctionName] [PASS] $($resultObject.Reason)"
        return $true
    }
}

function Invoke-PreActionDecisionLogic {
    <#
    .SYNOPSIS
        Implements decision logic for PreAction scenario (before making changes that may require reboot).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Result,
        
        [Parameter(Mandatory = $true)]
        $PolicyContext,
        
        [Parameter(Mandatory = $true)]
        $UserActivity,
        
        [Parameter(Mandatory = $true)]
        $RebootRequirements,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxUserIdleMinutes,
        
        [Parameter(Mandatory = $true)]
        [bool]$OverrideSuppression,
        
        [Parameter(Mandatory = $true)]
        [bool]$AllowUserCancel,
        
        [Parameter(Mandatory = $true)]
        [int]$PromptTimeoutMinutes,
        
        [Parameter(Mandatory = $true)]
        [bool]$WhatIf,
        
        [Parameter(Mandatory = $true)]
        $Computer
    )

    $FunctionName = "Invoke-PreActionDecisionLogic"
    Write-Host "[$ScriptName - $FunctionName] Evaluating PreAction scenario..."

    # Step 1: Check if existing pending reboot should block the operation
    if ($RebootRequirements.IsRebootPending -and $RebootRequirements.RebootWillBeRequired) {
        Write-Host "[$ScriptName - $FunctionName] Critical pending reboot detected: $($RebootRequirements.CriticalSources -join ', ')"
        
        # Check platform policy vs override
        if ($PolicyContext.RebootPreference -eq "Suppress" -and -not $OverrideSuppression) {
            $Result.ShouldProceed = $false
            $Result.Reason = "Critical pending reboot exists and platform policy suppresses reboots. Cannot proceed safely."
            $Result.RecommendedAction = "Clear pending reboot manually or enable override suppression"
            return $Result
        }
        
        # Check user activity for reboot feasibility
        $userActivityCheck = Test-UserActivityForReboot -UserActivity $UserActivity -MaxUserIdleMinutes $MaxUserIdleMinutes
        
        if (-not $userActivityCheck.IsSafe) {
            $Result.ShouldProceed = $false
            $Result.ShouldPromptUser = $userActivityCheck.ShouldPrompt
            $Result.UserInteractionMode = if ($userActivityCheck.ShouldPrompt) { "Prompt" } else { "None" }
            $Result.Reason = "Critical pending reboot exists but user activity prevents safe reboot: $($userActivityCheck.Reason)"
            $Result.RecommendedAction = "Wait for user to become inactive or clear pending reboot manually"
            return $Result
        }
        
        # User activity allows reboot - should we clear it before proceeding?
        $Result.ShouldProceed = $true
        $Result.ShouldReboot = $true
        $Result.ShouldPromptUser = $AllowUserCancel
        $Result.UserInteractionMode = if ($AllowUserCancel) { "Prompt" } else { "Notify" }
        $Result.Reason = "Critical pending reboot will be cleared before proceeding with software changes."
        $Result.RecommendedAction = if ($WhatIf) { "Would clear pending reboot, then proceed" } else { "Clear pending reboot, then proceed" }
        
        if ($OverrideSuppression -and $PolicyContext.RebootPreference -eq "Suppress") {
            $Result.OverrideApplied = $true
        }
        
        return $Result
    }
    
    # Step 2: No critical pending reboot - check if we should proceed
    if ($PolicyContext.RebootPreference -eq "Suppress" -and -not $OverrideSuppression) {
        $Result.ShouldProceed = $false
        $Result.Reason = "Platform policy suppresses reboots and no override specified. Cannot guarantee successful operation."
        $Result.RecommendedAction = "Enable override suppression for critical software operations"
        return $Result
    }
    
    # Step 3: Safe to proceed
    $Result.ShouldProceed = $true
    $Result.Reason = "No critical blocking conditions detected. Safe to proceed with software changes."
    $Result.RecommendedAction = "Proceed with planned software operation"
    
    if ($OverrideSuppression -and $PolicyContext.RebootPreference -eq "Suppress") {
        $Result.OverrideApplied = $true
    }
    
    Write-Host "[$ScriptName - $FunctionName] PreAction evaluation complete: Should proceed = $($Result.ShouldProceed)"
    return $Result
}

function Invoke-PostActionDecisionLogic {
    <#
    .SYNOPSIS
        Implements decision logic for PostAction scenario (after changes requiring reboot).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Result,
        
        [Parameter(Mandatory = $true)]
        $PolicyContext,
        
        [Parameter(Mandatory = $true)]
        $UserActivity,
        
        [Parameter(Mandatory = $true)]
        $RebootRequirements,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxUserIdleMinutes,
        
        [Parameter(Mandatory = $true)]
        [bool]$AllowUserCancel,
        
        [Parameter(Mandatory = $true)]
        [int]$PromptTimeoutMinutes,
        
        [Parameter(Mandatory = $true)]
        [bool]$WhatIf,
        
        [Parameter(Mandatory = $true)]
        $Computer
    )

    $FunctionName = "Invoke-PostActionDecisionLogic"
    Write-Host "[$ScriptName - $FunctionName] Evaluating PostAction scenario..."

    # PostAction scenario: Changes have been made that require reboot
    # Software is in an incomplete state - reboot is mandatory for proper function
    
    # Step 1: Check user activity
    $userActivityCheck = Test-UserActivityForReboot -UserActivity $UserActivity -MaxUserIdleMinutes $MaxUserIdleMinutes
    
    if (-not $userActivityCheck.IsSafe) {
        # User is active - we must still reboot but should give notification
        $Result.ShouldProceed = $true  # Changes already made, must complete
        $Result.ShouldReboot = $true   # Reboot is mandatory
        $Result.ShouldPromptUser = $true
        $Result.UserInteractionMode = "Notify"  # User cannot cancel post-action reboot
        $Result.Reason = "Software changes require immediate reboot to complete. User is active but will be notified."
        $Result.RecommendedAction = if ($WhatIf) { "Would notify user and reboot" } else { "Notify user and proceed with reboot" }
    } else {
        # User is not active - safe to reboot immediately
        $Result.ShouldProceed = $true
        $Result.ShouldReboot = $true
        $Result.ShouldPromptUser = $false
        $Result.UserInteractionMode = "None"
        $Result.Reason = "Software changes require reboot and user is not active. Safe to reboot immediately."
        $Result.RecommendedAction = if ($WhatIf) { "Would reboot immediately" } else { "Reboot immediately" }
    }

    # PostAction scenario always proceeds regardless of platform policy
    # because software is already in incomplete state
    if ($PolicyContext.RebootPreference -eq "Suppress") {
        $Result.OverrideApplied = $true
        Write-Host "[$ScriptName - $FunctionName] Overriding 'Suppress' policy - software changes mandate reboot completion"
    }
    
    Write-Host "[$ScriptName - $FunctionName] PostAction evaluation complete: Mandatory reboot required"
    return $Result
}

function Invoke-ClearPendingDecisionLogic {
    <#
    .SYNOPSIS
        Implements decision logic for ClearPending scenario (clear existing pending reboot before proceeding).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Result,
        
        [Parameter(Mandatory = $true)]
        $PolicyContext,
        
        [Parameter(Mandatory = $true)]
        $UserActivity,
        
        [Parameter(Mandatory = $true)]
        $RebootRequirements,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxUserIdleMinutes,
        
        [Parameter(Mandatory = $true)]
        [bool]$OverrideSuppression,
        
        [Parameter(Mandatory = $true)]
        [bool]$AllowUserCancel,
        
        [Parameter(Mandatory = $true)]
        [int]$PromptTimeoutMinutes,
        
        [Parameter(Mandatory = $true)]
        [bool]$WhatIf,
        
        [Parameter(Mandatory = $true)]
        $Computer
    )

    $FunctionName = "Invoke-ClearPendingDecisionLogic"
    Write-Host "[$ScriptName - $FunctionName] Evaluating ClearPending scenario..."

    # Step 1: Check if there's actually a pending reboot to clear
    if (-not $RebootRequirements.IsRebootPending) {
        $Result.ShouldProceed = $true
        $Result.Reason = "No pending reboot detected. No action needed."
        $Result.RecommendedAction = "Continue with planned operations"
        return $Result
    }
    
    Write-Host "[$ScriptName - $FunctionName] Pending reboot detected: $($RebootRequirements.RebootSources -join ', ')"
    
    # Step 2: Check platform policy vs override
    if ($PolicyContext.RebootPreference -eq "Suppress" -and -not $OverrideSuppression) {
        $Result.ShouldProceed = $false
        $Result.Reason = "Pending reboot exists but platform policy suppresses reboots. Cannot clear."
        $Result.RecommendedAction = "Enable override suppression or manually clear pending reboot"
        return $Result
    }
    
    # Step 3: Check user activity for reboot feasibility
    $userActivityCheck = Test-UserActivityForReboot -UserActivity $UserActivity -MaxUserIdleMinutes $MaxUserIdleMinutes
    
    if (-not $userActivityCheck.IsSafe) {
        $Result.ShouldProceed = $false
        $Result.ShouldPromptUser = $userActivityCheck.ShouldPrompt
        $Result.UserInteractionMode = if ($userActivityCheck.ShouldPrompt) { "Prompt"
    } else { "None" }
        $Result.Reason = "Pending reboot exists but user activity prevents safe reboot: $($userActivityCheck.Reason)"
        $Result.RecommendedAction = "Wait for user to become inactive or schedule reboot"
        return $Result
    }
    
    # Step 4: Safe to clear pending reboot
    $Result.ShouldProceed = $true
    $Result.ShouldReboot = $true
    $Result.ShouldPromptUser = $AllowUserCancel
    $Result.UserInteractionMode = if ($AllowUserCancel) { "Prompt" } else { "Notify" }
    $Result.Reason = "Pending reboot will be cleared. $($userActivityCheck.Reason)"
    $Result.RecommendedAction = if ($WhatIf) { "Would clear pending reboot" } else { "Clear pending reboot" }
    
    if ($OverrideSuppression -and $PolicyContext.RebootPreference -eq "Suppress") {
        $Result.OverrideApplied = $true
    }
    
    Write-Host "[$ScriptName - $FunctionName] ClearPending evaluation complete: Should clear = $($Result.ShouldReboot)"
    return $Result
}

function Invoke-C9InstallWithChildProcesses {
    <#
    .SYNOPSIS
        (Metascript Orchestrator) Executes a process with advanced timeout and child-process handling on an endpoint.
    .DESCRIPTION
        This Metascript function orchestrates the execution of an executable or MSI on a target endpoint.
        It uses Invoke-ImmyCommand to run a robust script block in the endpoint's System context.
        The endpoint script monitors the process, captures all output, and gracefully terminates the entire process tree on timeout.
        This function is the definitive, robust replacement for simple 'Start-Process -Wait' calls.
    .PARAMETER Path
        The full path to the executable or MSI file *on the endpoint*.
    .PARAMETER Arguments
        Optional command-line arguments to pass to the executable.
    .PARAMETER TimeoutInSeconds
        The maximum duration in seconds to allow the process (and its children) to run before forceful termination. Default is 300.
    .PARAMETER Computer
        The target computer object. Defaults to the computer in the current context via (Get-ImmyComputer).
    .OUTPUTS
        A PSCustomObject containing the execution results from the endpoint:
        - ExitCode ([int])
        - StandardOutput ([string])
        - StandardError ([string])
    .EXAMPLE
        $installerPath = "C:\Temp\S1_Install\SentinelOneInstaller.exe"
        $installerArgs = "/SILENT /NORESTART SITE_TOKEN=..."
        
        $installResult = Invoke-C9InstallParentChild -Path $installerPath -Arguments $installerArgs -TimeoutInSeconds 900

        if ($installResult.ExitCode -ne 0) {
            throw "Installation failed with Exit Code: $($installResult.ExitCode). Error: $($installResult.StandardError)"
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Arguments = "",

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSeconds = 300,
        
        [Parameter(Mandatory = $false)]
        $Computer = (Get-ImmyComputer)
    )

    $FunctionName = "Invoke-C9InstallWithChildProcesses"

    Write-Host "[$ScriptName - $FunctionName] Orchestrating managed execution of '$Path' on endpoint '$($Computer.Name)'..."

    # The Invoke-ImmyCommand timeout should be slightly longer than the internal process timeout
    # to ensure the script block itself doesn't get killed prematurely.
    $commandTimeout = $TimeoutInSeconds + 30 

    # We use Invoke-ImmyCommand to bridge to the System context.
    # The entire process execution logic lives inside this script block.
    $result = Invoke-ImmyCommand -Computer $Computer -Timeout $commandTimeout -ScriptBlock {
        
        # We access Metascript variables using the reliable $using: scope modifier.
        # This avoids the buggy -ArgumentList parameter and param() block pattern.

        # --- Start of Endpoint Execution Logic ---
        $localPath = $using:Path
        $localArguments = $using:Arguments
        $localTimeoutInSeconds = $using:TimeoutInSeconds

        Write-Host "[$using:ScriptName - $using:FunctionName] Endpoint received execution request for '$localPath'"

        if (-not (Test-Path $localPath)) {
            throw "[$using:ScriptName - $using:FunctionName] The specified path '$localPath' does not exist on the endpoint."
        }

        $isMSI = ($localPath -like "*.msi")

        $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        if ($isMSI) {
            $StartInfo.FileName = "msiexec.exe"
            # For msiexec, arguments must be handled carefully.
            $StartInfo.Arguments = "/i `"$localPath`" $localArguments /qn /L*v `"C:\Windows\Temp\MSI-C9-Install-Log-$($pid).log`""
        } else {
            $StartInfo.FileName = $localPath
            $StartInfo.Arguments = $localArguments
        }
        $StartInfo.UseShellExecute = $false
        $StartInfo.RedirectStandardOutput = $true
        $StartInfo.RedirectStandardError = $true
        $StartInfo.CreateNoWindow = $true

        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $StartInfo

        # This helper function is defined directly inside the script block,
        # making it available only for this execution.
        function Get-C9ChildProcesses {
            param ([int]$ParentProcessId)
            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $ParentProcessId"
            foreach ($child in $children) {
                $child
                # The recursive call to find grandchildren.
                Get-C9ChildProcesses -ParentProcessId $child.ProcessId
            }
        }

        try {
            $Process.Start() | Out-Null
            Write-Host "[$using:ScriptName - $using:FunctionName] Started process: $($StartInfo.FileName) with PID: $($Process.Id)"

            $Exited = $Process.WaitForExit($localTimeoutInSeconds * 1000)
            
            if (-not $Exited) {
                Write-Warning "[$using:ScriptName - $using:FunctionName] Process exceeded timeout of $localTimeoutInSeconds seconds. Terminating process tree..."

                $ChildProcesses = Get-C9ChildProcesses -ParentProcessId $Process.Id
                if ($ChildProcesses) {
                    # Terminate children first, from the bottom up (though order isn't critical here).
                    foreach ($Child in ($ChildProcesses | Sort-Object -Descending)) {
                        try {
                            Stop-Process -Id $Child.ProcessId -Force -ErrorAction Stop
                            Write-Host "[$using:ScriptName - $using:FunctionName] Terminated child process: $($Child.Name) (PID $($Child.ProcessId))"
                        } catch {
                            Write-Warning "[$using:ScriptName - $using:FunctionName] Failed to terminate child process PID $($Child.ProcessId): $($_.Exception.Message)"
                        }
                    }
                }

                if (-not $Process.HasExited) {
                    Write-Warning "[$using:ScriptName - $using:FunctionName] Killing main process: $($Process.ProcessName) (PID $($Process.Id))"
                    $Process.Kill()
                }
            }

            $StandardOutput = $Process.StandardOutput.ReadToEnd()
            $StandardError = $Process.StandardError.ReadToEnd()
            $ExitCode = $Process.ExitCode
            
            # --- This is the object that will be returned to the Metascript ---
            return [PSCustomObject]@{
                ExitCode       = $ExitCode
                StandardOutput = $StandardOutput
                StandardError  = $StandardError
            }

        } catch {
            throw "An error occurred during endpoint process execution: $_"
        } finally {
            if ($Process -and -not $Process.HasExited) {
                try { $Process.Kill() } catch {}
            }
            if ($Process) {
                $Process.Dispose()
            }
        }
        # --- End of Endpoint Execution Logic ---
    }

    # Log the full results received back in the Metascript log for visibility.
    if ($result) {
        Write-Host -ForegroundColor Green "[$ScriptName - $FunctionName] Endpoint execution complete. Exit Code: $($result.ExitCode)."
        if (-not [string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            Write-Host -ForegroundColor Cyan "[$ScriptName - $FunctionName] --- Endpoint Standard Output ---"
            Write-Host -ForegroundColor Green $result.StandardOutput
            Write-Host -ForegroundColor Cyan "---------------------------------"
        }
        if (-not [string]::IsNullOrWhiteSpace($result.StandardError)) {
            Write-Warning "--- Endpoint Standard Error ---"
            Write-Warning $result.StandardError
            Write-Warning "-------------------------------"
        }
    }

    return $result
}

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

    #Write-Host "[$ScriptName - $FunctionName] Preparing to execute '$FilePath' with arguments: $($ArgumentList -join ' ')"

    # We use the $using: scope modifier to reliably pass variables into the script block,
    # bypassing the unreliable -ArgumentList parameter binding mechanism.
    $result = Invoke-ImmyCommand -Computer $Computer -Timeout $TimeoutSeconds -ScriptBlock {
        
        # We do not use a param() block here; we access the variables directly via $using:
        #Write-Host "[$using:ScriptName - $using:FunctionName] Endpoint received command: '$($using:FilePath)'"
        #Write-Host "[$using:ScriptName - $using:FunctionName] Endpoint received argument: '$($using:ArgumentList -join ' ')'"
        
        if (-not (Test-Path -Path $using:FilePath -PathType Leaf)) {
            throw "[$using:ScriptName - $using:FunctionName] Executable not found at path: $($using:FilePath)"
        }

        # This logic correctly handles arguments with spaces by quoting them.
        $formattedArgs = foreach ($arg in $using:ArgumentList) {
            if ($arg -match '\s') { "`"$arg`"" } else { $arg }
        }
        $argumentString = $formattedArgs -join ' '

        #Write-Host "[$using:ScriptName - $using:FunctionName] Executing: `"$($using:FilePath)`" $argumentString"

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
        } catch {
            throw "[$using:ScriptName - $using:FunctionName] Failed to start or monitor process '$($using:FilePath)'. Error: $_"
        } finally {
            if ($p) {
                $p.Dispose()
            }
        }

    } # Note: No -ArgumentList is used here.

    # Log the full results to the Metascript log for excellent visibility.
    if ($result) {
        #Write-Host -ForegroundColor Green "[$ScriptName - $FunctionName] Command finished with Exit Code: $($result.ExitCode)."
        if (-not [string]::IsNullOrWhiteSpace($result.StandardOutput)) {
            #Write-Host -ForegroundColor Cyan "[$ScriptName - $FunctionName] --- Start Standard Output ---"
            #Write-Host -ForegroundColor Green $result.StandardOutput
            #Write-Host -ForegroundColor Cyan "[$ScriptName - $FunctionName] --- End Standard Output ---"
        }
        if (-not [string]::IsNullOrWhiteSpace($result.StandardError)) {
            #Write-Warning "--- Start Standard Error ---"
            #Write-Warning $result.StandardError
            #Write-Warning "--- End Standard Error ---"
        }
    }

    return $result
}

function Format-C9ObjectForDisplay {
    <#
    .SYNOPSIS
        (Helper) Converts any simple or single-level nested PSCustomObject into a flat array for clean table display.
    .DESCRIPTION
        This generic function iterates through an object's properties and flattens them for logging.
        - If a property's value is a simple type (string, bool, int), it creates a single row.
        - If a property's value is another object (a nested object), it iterates through that sub-object's properties,
          using the parent property's name as the category for those rows.
        This provides a universal, recursive-like formatting tool for our scripts.
    .PARAMETER InputObject
        The PSCustomObject to format for display.
    .PARAMETER DefaultCategory
        A category name to use for any top-level, non-nested properties. Defaults to "General".
    .OUTPUTS
        An array of simple PSCustomObjects, each with Category, Property, and Value properties, ready for Format-Table.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$InputObject,

        [Parameter(Mandatory = $false)]
        [string]$DefaultCategory = "General"
    )

    $FunctionName = "Format-C9ObjectForDisplay"
    $displayRows = @()

    # =========================================================================
    # --- BEGIN CORRECTED SECTION ---
    # =========================================================================
    # This helper is now hardened to prevent the Substring error.
    function ConvertTo-TitleCase ($str) {
        if ([string]::IsNullOrWhiteSpace($str)) {
            return $str
        }
        return -join ($str -split '(?=[A-Z])' | ForEach-Object {
            # Check if the chunk is longer than one character before calling Substring(1)
            if ($_.Length -gt 1) {
                $_.Substring(0,1).ToUpper() + $_.Substring(1) + ' '
            } else {
                # If it's only one character, just uppercase it.
                $_.ToUpper() + ' '
            }
        }).Trim()
    }
    # =========================================================================
    # --- END CORRECTED SECTION ---
    # =========================================================================

    # The rest of the function logic remains the same.
    foreach ($topLevelProperty in $InputObject.PSObject.Properties) {
        $topLevelName = $topLevelProperty.Name
        $topLevelValue = $topLevelProperty.Value

        if ($topLevelValue -is [System.Management.Automation.PSCustomObject] -and $topLevelValue.PSObject.Properties.Count -gt 0) {
            $categoryName = ConvertTo-TitleCase $topLevelName
            foreach ($innerProperty in $topLevelValue.PSObject.Properties) {
                $propName = $innerProperty.Name
                $propValue = $innerProperty.Value
                $displayValue = ""
                if ($null -eq $propValue) {
                    $displayValue = "(not set)"
                } elseif ($propValue -is [bool]) {
                    $displayValue = if ($propValue) { "[TRUE]" } else { "[FALSE]" }
                } elseif ($propValue -is [array]) {
                    $displayValue = $propValue -join ", "
                    if ([string]::IsNullOrWhiteSpace($displayValue)) {
                        $displayValue = "(empty list)"
                    }
                } else {
                    $displayValue = "$propValue"
                }
                $row = New-Object -TypeName PSObject
                Add-Member -InputObject $row -MemberType NoteProperty -Name 'Category' -Value $categoryName
                Add-Member -InputObject $row -MemberType NoteProperty -Name 'Property' -Value (ConvertTo-TitleCase -str $propName)
                Add-Member -InputObject $row -MemberType NoteProperty -Name 'Value' -Value $displayValue
                $displayRows += $row
            }
        } else {
            $propName = $topLevelName
            $propValue = $topLevelValue
            $displayValue = ""
            if ($null -eq $propValue) {
                $displayValue = "(not set)"
            } elseif ($propValue -is [bool]) {
                $displayValue = if ($propValue) {
                    "[TRUE]"
                } else {
                    "[FALSE]"
                }
            } elseif ($propValue -is [array]) {
                $displayValue = $propValue -join ", "
                if ([string]::IsNullOrWhiteSpace($displayValue)) {
                    $displayValue = "(empty list)"
                }
            } else {
                $displayValue = "$propValue"
            }
            $row = New-Object -TypeName PSObject
            Add-Member -InputObject $row -MemberType NoteProperty -Name 'Category' -Value $DefaultCategory
            Add-Member -InputObject $row -MemberType NoteProperty -Name 'Property' -Value (ConvertTo-TitleCase -str $propName)
            Add-Member -InputObject $row -MemberType NoteProperty -Name 'Value' -Value $displayValue
            $displayRows += $row
        }
    }

    return $displayRows
}

function Get-C9ComprehensiveSystemState {
    <#
    .SYNOPSIS
        (Ultimate Get Orchestrator) Gathers all necessary state data from an endpoint.
    #>
    [CmdletBinding()]
    param()

    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host "--- BEGINNING ULTIMATE COMPREHENSIVE SYSTEM STATE ASSESSMENT ---" -ForegroundColor Yellow

    # --- THIS IS THE PRIMARY FIX ---
    # We must import the module containing the S1-specific functions we need to call.
    Import-Module "C9SentinelOneMeta"
    
    $systemState = New-Object -TypeName PSObject
    
    # --- This function now orchestrates QUIET helpers ---
    Add-Member -InputObject $systemState -MemberType NoteProperty -Name 'S1Status' -Value (Get-C9S1ComprehensiveStatus)
    Add-Member -InputObject $systemState -MemberType NoteProperty -Name 'RebootRequirements' -Value (Get-C9SystemRebootRequirements)
    Add-Member -InputObject $systemState -MemberType NoteProperty -Name 'UserActivity' -Value (Get-C9UserActivityStatus)
    Add-Member -InputObject $systemState -MemberType NoteProperty -Name 'RebootPolicy' -Value (Get-C9RebootPolicyContext)
    
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host "--- ULTIMATE COMPREHENSIVE SYSTEM STATE ASSESSMENT COMPLETE ---" -ForegroundColor Yellow
    
    return $systemState
}

Export-ModuleMember -Function *