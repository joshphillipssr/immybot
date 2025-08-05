function Invoke-ImmyCommandWithLogging {
    <#
    .SYNOPSIS
        Wrapper for Invoke-ImmyCommand that includes automatic logging functionality.
    .DESCRIPTION
        This function wraps Invoke-ImmyCommand and automatically injects logging capabilities
        into the scriptblock, making Write-C9LogMessage available in the remote context.
    .PARAMETER ScriptBlock
        The script block to execute on the remote computer.
    .PARAMETER Computer
        The computer to execute against. Defaults to current session computer.
    .PARAMETER Context
        Execution context: "System" or "User". Defaults to "System".
    .PARAMETER ArgumentList
        Arguments to pass to the script block.
    .PARAMETER Timeout
        Timeout in seconds. Default is 120.
    .PARAMETER LogPrefix
        Custom prefix for log messages. Auto-detects from ScriptName if not provided.
    .PARAMETER Parallel
        Execute on multiple computers simultaneously.
    .EXAMPLE
        Invoke-ImmyCommandWithLogging {
            Log "Starting remote operation" -Type Info
            # Your remote operations here
            Log "Remote operation completed" -Type Success
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        $Computer,
        
        [Parameter()]
        [string]$ContextString = "System",  # Fixed: was "Context"
        
        [Parameter()]
        [array]$ArgumentList,
        
        [Parameter()]
        [int]$Timeout,
        
        [Parameter()]
        [int]$ConnectTimeout,
        
        [Parameter()]
        [int]$AgentConnectionWaitTimeout,
        
        [Parameter()]
        [switch]$Parallel,
        
        [Parameter()]
        [switch]$DisableConnectTimeoutWarnings,
        
        [Parameter()]
        [switch]$IncludeLocals,
        
        [Parameter()]
        [string]$ScriptType,
        
        [Parameter()]
        [string]$ScriptName,
        
        [Parameter()]
        $CircuitBreakerPolicy,
        
        [Parameter()]
        [string]$LogPrefix
    )

    # Auto-detect log prefix
    if (-not $LogPrefix) {
        $LogPrefix = if ($ScriptName) { "[$ScriptName-Remote]" } else { "[Remote]" }
    }

    # Create enhanced scriptblock with logging injected
    $WrappedScriptBlock = [scriptblock]::Create(@"
        # Inject logging function
        function Write-C9LogMessage {
            param([string]`$Message, [string]`$Type = 'Info')
            `$Prefix = '$LogPrefix'
            switch (`$Type) {
                'Header'  { Write-Host "`$Prefix === `$Message ===" -ForegroundColor Cyan }
                'Info'    { Write-Host "`$Prefix → `$Message" -ForegroundColor Cyan }
                'Success' { Write-Host "`$Prefix ✓ `$Message" -ForegroundColor Green }
                'Warning' { Write-Host "`$Prefix ⚠ `$Message" -ForegroundColor Yellow }
                'Error'   { Write-Host "`$Prefix ✗ `$Message" -ForegroundColor Red }
                'Verbose' { Write-Host "`$Prefix   → `$Message" -ForegroundColor Gray }
            }
        }
        function Log { param(`$Message, `$Type = 'Info') Write-C9LogMessage `$Message -Type `$Type }
        
        # Execute original scriptblock
        & {$($ScriptBlock.ToString())}
"@)

    # Build parameters hash - only include non-null values
    $InvokeParams = @{
        ScriptBlock = $WrappedScriptBlock
        ContextString = $ContextString
    }
    
    # Only add optional parameters if they have values
    if ($Computer) { $InvokeParams.Computer = $Computer }
    if ($ArgumentList) { $InvokeParams.ArgumentList = $ArgumentList }
    if ($Timeout) { $InvokeParams.Timeout = $Timeout }
    if ($ConnectTimeout) { $InvokeParams.ConnectTimeout = $ConnectTimeout }
    if ($AgentConnectionWaitTimeout) { $InvokeParams.AgentConnectionWaitTimeout = $AgentConnectionWaitTimeout }
    if ($Parallel) { $InvokeParams.Parallel = $Parallel }
    if ($DisableConnectTimeoutWarnings) { $InvokeParams.DisableConnectTimeoutWarnings = $DisableConnectTimeoutWarnings }
    if ($IncludeLocals) { $InvokeParams.IncludeLocals = $IncludeLocals }
    if ($ScriptType) { $InvokeParams.ScriptType = $ScriptType }
    if ($ScriptName) { $InvokeParams.ScriptName = $ScriptName }
    if ($CircuitBreakerPolicy) { $InvokeParams.CircuitBreakerPolicy = $CircuitBreakerPolicy }

    # Execute with proper parameter splatting
    Invoke-ImmyCommand @InvokeParams
}