<#
.SYNOPSIS
    A Metascript function that disables the SentinelOne agent's self-protection using a passphrase.
.DESCRIPTION
    This function is a dedicated tool for unprotecting a SentinelOne agent. It requires the agent's
    uninstall passphrase. It locates sentinelctl.exe on the endpoint and then executes the
    'unprotect' command, capturing all console output for diagnostics.
.PARAMETER Passphrase
    [string] The agent-specific uninstall passphrase. This is mandatory.
#>
function Set-C9SentinelOneUnprotect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Passphrase
    )

    # Pre-flight check. This action is impossible without a passphrase.
    if ([string]::IsNullOrWhiteSpace($Passphrase)) {
        Write-Warning "FATAL: Set-C9SentinelOneUnprotect was called without a passphrase. Aborting."
        return $null
    }

    Write-Host "Attempting to set agent protection state to 'Unprotect'..."

    # We use Invoke-ImmyCommand to run the command on the endpoint and get a structured result back.
    $resultObject = Invoke-ImmyCommand -ScriptBlock {
        param($Passphrase) # Receive the passphrase from the Metascript.

        try {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue
            if (-not $service) { return $null }

            $installDir = Split-Path -Path ($service.PathName.Trim('"')) -Parent
            $sentinelCtlPath = Join-Path -Path $installDir -ChildPath 'SentinelCtl.exe'
            if (-not (Test-Path -LiteralPath $sentinelCtlPath)) { return $null }

            # --- ROBUST CONSOLE CAPTURE PATTERN ---
            # 1. Build an ARRAY of arguments. This is the most reliable method.
            $argList = @('unprotect', '-k', $Passphrase)
            
            # 2. Use the call operator (&) with the argument array.
            # 3. Use '*> &1' to redirect ALL output streams into a single stream.
            $capturedOutput = & $sentinelCtlPath $argList *>&1
            
            # 4. Check the exit code of the last external program that ran.
            $exitCode = $LASTEXITCODE

            # 5. Prepare the final, structured result object.
            $result = @{
                Status = ($exitCode -eq 0)
                Output  = ($capturedOutput | Out-String).Trim()
            }
            
            return [PSCustomObject]$result

        } catch {
            Write-Warning "An unexpected error occurred during endpoint protection state change: $_"
            return $null
        }
    } -ArgumentList $Passphrase # Pass the passphrase into the script block.

    # This code runs back in the Metascript after the endpoint block is finished.
    if ($resultObject) {
        Write-Host "Protection state command completed."
    } else {
        Write-Warning "Could not get a valid result from the endpoint."
    }

    # Return the entire result object for inspection.
    return $resultObject
}