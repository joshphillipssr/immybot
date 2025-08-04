function Write-C9LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Verbose', 'Header', 'Debug')]
        [string]$Type = 'Info',
        
        [Parameter()]
        [string]$Prefix,  # Allow manual override
        
        [Parameter()]
        [switch]$NoNewline
    )
    # Import the logging function
    # Get-Script "Write-LogMessage" | Invoke-Expression
    # at the beginning of each script

    # === AUTO-DETECT CONTEXT IF NO PREFIX PROVIDED ===
    if (-not $Prefix) {
        $CallStack = Get-PSCallStack
        
        # Check if we're being called from within a function
        if ($CallStack.Count -gt 1) {
            $CallingFunction = $CallStack[1].FunctionName
            
            # If called from a function (not script scope), use function name
            if ($CallingFunction -and $CallingFunction -ne '<ScriptBlock>') {
                $Prefix = "[$CallingFunction]"
            } else {
                # Called from script scope, use ScriptName
                $Prefix = if ($ScriptName) { "[$ScriptName]" } else { "[Script]" }
            }
        } else {
            # Fallback to ScriptName
            $Prefix = if ($ScriptName) { "[$ScriptName]" } else { "[Script]" }
        }
    }
    
    $WriteHostParams = @{
        NoNewline = $NoNewline
    }
    
    switch ($Type) {
        'Header'  { 
            Write-Host "$Prefix === $Message ===" -ForegroundColor Cyan @WriteHostParams
        }
        'Info'    { 
            Write-Host "$Prefix → $Message" -ForegroundColor Cyan @WriteHostParams
        }
        'Success' { 
            Write-Host "$Prefix ✓ $Message" -ForegroundColor Green @WriteHostParams
        }
        'Warning' { 
            Write-Host "$Prefix ⚠ $Message" -ForegroundColor Yellow @WriteHostParams
        }
        'Error'   { 
            Write-Host "$Prefix ✗ $Message" -ForegroundColor Red @WriteHostParams
        }
        'Verbose' { 
            Write-Host "$Prefix   → $Message" -ForegroundColor Gray @WriteHostParams
        }
        'Debug'   { 
            Write-Host "$Prefix [DEBUG] $Message" -ForegroundColor DarkGray @WriteHostParams
        }
    }
}

Set-Alias -Name "Log" -Value "Write-C9LogMessage"
Export-ModuleMember -Function Write-C9LogMessage -Alias Log