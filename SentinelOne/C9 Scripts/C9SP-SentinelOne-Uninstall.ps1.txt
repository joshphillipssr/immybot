# =================================================================================
# Name:     C9SP-SentinelOne-Uninstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param(
    [string]$rebootPreference
    #[string]$InstallerFile
)

$tempUninstallDir = $null
$InstallerFile = "C:\ProgramData\ImmyBot\S1\Installer\SentinelOneInstaller_windows_64bit_v24_2_3_471.exe"

# Import all modules needed.
Import-Module "C9MetascriptHelpers" -Verbose:$false
Import-Module "C9SentinelOneMeta"   -Verbose:$false
Import-Module "C9SentinelOneCloud"  -Verbose:$false

$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"

# =========================================================================
# --- Phase 0: Ultimate Comprehensive Status Assessment (Corrected Logic) ---
# =========================================================================
# Step 1: Gather the standard, universal system state.
# This block is now identical to the Test script's "Get" phase.
if ($null -eq $script:systemState) {
    Write-Host "[$ScriptName] Phase 0: Performing ultimate comprehensive status assessment..."
    $script:systemState = Get-C9ComprehensiveSystemState
    
    # Log the detailed findings for excellent diagnostics on the first run.
    $formattedStatus = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
    Write-Host "----------------- COMPREHENSIVE SYSTEM STATE -----------------"
    Write-Host $formattedStatus
    Write-Host "------------------------------------------------------------"
} else {
    Write-Host "[$ScriptName] Phase 0: Resuming with persisted system state from before reboot."
}

# Step 2: Gather the uninstall-specific credentials and add them to our state object.
# We check if the property already exists to prevent errors on a post-reboot run.
if ($null -eq $script:systemState.CloudCredentials) {
    Write-Host "[$ScriptName] Phase 0: Gathering additional cloud credentials for uninstall..."
    $passphrase = Get-IntegrationAgentUninstallToken -ErrorAction SilentlyContinue
    $siteToken = Get-IntegrationAgentInstallToken -ErrorAction SilentlyContinue
    $cloudCreds = [ordered]@{
        Passphrase    = $passphrase
        SiteToken     = $siteToken
        HasPassphrase = (-not [string]::IsNullOrWhiteSpace($passphrase))
        HasSiteToken  = (-not [string]::IsNullOrWhiteSpace($siteToken))
    }
    # Add the new credentials object to our persistent state variable.
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'CloudCredentials' -Value (New-Object -TypeName PSObject -Property $cloudCreds)
    Write-Host "[$ScriptName] Phase 0: Cloud credentials have been added to the system state."
    Write-Host "[$ScriptName] SiteToken is $siteToken"
    Write-Host "[$ScriptName] Passphrase is $passphrase"
}

Write-Host "[$ScriptName] Phase 0 Complete. System state has been fully captured."


# =========================================================================
# --- Phase 1: Attempt Standard Uninstall (Unprotect-First Strategy) ---
# =========================================================================
Write-Host "[$ScriptName] Phase 1: Attempting Standard Uninstall..."

# Add state-tracking variables to our persistent object for the next phases.
if ($null -eq $script:systemState.StandardUninstallAttempted) {
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'StandardUninstallAttempted' -Value $false
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'StandardUninstallSucceeded' -Value $false
}

# This entire process is conditional on having the passphrase for the unprotect step.
if ($script:systemState.CloudCredentials.HasPassphrase) {
    try {
        Write-Host "[$ScriptName] [STANDARD] Passphrase found. Beginning two-step standard uninstall process..."
        
        # --- Step 1: Unprotect the Agent (Your proven-effective prerequisite) ---
        Write-Host "[$ScriptName] [STANDARD] Step 1 of 2: Disabling agent self-protection..."
        Set-C9SentinelOneUnprotect -Passphrase $script:systemState.CloudCredentials.Passphrase
        
        # --- Step 2: Execute the Standard Uninstall ---
        Write-Host "[$ScriptName] [STANDARD] Step 2 of 2: Executing the standard uninstall method..."
        $uninstallResult = Invoke-C9S1StandardUninstall -CloudCredentials $script:systemState.CloudCredentials -InstallerFile $InstallerFile
        
        if (-not $uninstallResult.Success) {
            # If the specialist function reports failure, we throw its reason to the catch block.
            throw $uninstallResult.Reason
        }
        
        Write-Host "[$ScriptName] [STANDARD] Standard Uninstall action completed."
        $script:systemState.StandardUninstallSucceeded = $true

    } catch {
        # Log the failure but do not throw, so we can proceed to the "Verify" step later.
        Write-Warning "[$ScriptName] [STANDARD] The Standard Uninstall process failed. Reason: $_"
        $script:systemState.StandardUninstallSucceeded = $false
    }
}
else {
    Write-Warning "[$ScriptName] [STANDARD] SKIPPED: Standard uninstall requires a passphrase for the unprotect step, which was not found."
}

# Mark that we have completed this attempt, regardless of outcome.
$script:systemState.StandardUninstallAttempted = $true
Write-Host "[$ScriptName] Phase 1 Complete."