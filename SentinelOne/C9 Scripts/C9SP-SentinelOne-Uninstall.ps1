# =================================================================================
# Name:     C9SP-SentinelOne-Uninstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param(
    [string]$rebootPreference,
    [string]$InstallerFile
)

# Import all modules needed.
Import-Module "C9MetascriptHelpers" -Verbose:$false
Import-Module "C9SentinelOneMeta"   -Verbose:$false
Import-Module "C9SentinelOneCloud"  -Verbose:$false

# Set preference for this script's execution
$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"

# =================================================================================
# --- Initial State Loading ---
# =================================================================================
# Step 1: Load the persisted installer variables from the JSON file.
Write-Host "[$ScriptName] Attempting to retrieve persisted installer variables from JSON..."
$persistedVars = Get-C9S1InstallerState

# Step 2: Initialize the script-scoped variables with the loaded data.
if ($null -ne $persistedVars) {
    $script:installerFolder = $persistedVars.InstallerFolder
    $script:installerFile = $persistedVars.InstallerFile
    $script:installerLogFile = $persistedVars.InstallerLogFile
} else {
    Write-Warning "[$ScriptName] Could not load installer state from JSON. Will fall back to platform-provided variables if available."
    $script:installerFolder = ""
    $script:installerFile = ""
    $script:installerLogFile = ""
}

# =========================================================================
# --- Phase 0: Comprehensive Status Assessment ---
# =========================================================================
# Step 1: Gather the standard, universal system state.
if ($null -eq $script:systemState) {
    Write-Host "[$ScriptName] Phase 0: Performing comprehensive status assessment..."
    $script:systemState = Get-C9ComprehensiveSystemState
    
    $formattedStatus = Format-C9ObjectForDisplay -InputObject $script:systemState | Format-Table -AutoSize | Out-String
    Write-Host "----------------- COMPREHENSIVE SYSTEM STATE -----------------"
    Write-Host $formattedStatus
    Write-Host "------------------------------------------------------------"
} else {
    Write-Host "[$ScriptName] Phase 0: Resuming with persisted system state from before reboot."
}

# Step 2: Gather uninstall-specific credentials and add them to state object.
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
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'CloudCredentials' -Value (New-Object -TypeName PSObject -Property $cloudCreds)
    Write-Host "[$ScriptName] Phase 0: Cloud credentials gathered. Has Passphrase: $($cloudCreds.HasPassphrase), Has Site Token: $($cloudCreds.HasSiteToken)."
}

# Step 3: Determine the definitive installer path and add it to the state object.
if ($null -eq $script:systemState.InstallerFilePath) {
    $definitiveInstallerFile = ""
    if (-not [string]::IsNullOrWhiteSpace($script:installerFile)) {
        # Prioritize the path from our JSON file.
        $definitiveInstallerFile = $script:installerFile
        Write-Host "[$ScriptName] Using persisted installer path from JSON: $definitiveInstallerFile"
    } elseif (-not [string]::IsNullOrWhiteSpace($InstallerFile)) {
        # Fall back to the platform-provided parameter.
        $definitiveInstallerFile = $InstallerFile
        Write-Host "[$ScriptName] Using platform-provided installer path: $definitiveInstallerFile"
    }
    
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'InstallerFilePath' -Value $definitiveInstallerFile
}

Write-Host "[$ScriptName] Phase 0 Complete. System state has been fully captured."


# =========================================================================
# --- Phase 1: Attempt Standard Uninstall (Unprotect-First Strategy) ---
# =========================================================================
Write-Host "[$ScriptName] Phase 1: Attempting Standard Uninstall..."

if ($null -eq $script:systemState.StandardUninstallAttempted) {
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'StandardUninstallAttempted' -Value $false
    Add-Member -InputObject $script:systemState -MemberType NoteProperty -Name 'StandardUninstallSucceeded' -Value $false
}

# Pre-flight check: This entire phase is only useful if we have a path to the installer file.
if (-not [string]::IsNullOrWhiteSpace($script:systemState.InstallerFilePath)) {
    try {
        Write-Host "[$ScriptName] [STANDARD] Installer file path found. Beginning standard uninstall process..."

        # Step 1: Conditionally unprotect the agent ONLY if a passphrase exists.
        if ($script:systemState.CloudCredentials.HasPassphrase) {
            Write-Host "[$ScriptName] [STANDARD] Passphrase found. Disabling agent self-protection as a prerequisite..."
            Set-C9SentinelOneUnprotect -Passphrase $script:systemState.CloudCredentials.Passphrase
        } else {
            Write-Warning "[$ScriptName] [STANDARD] No passphrase found. Skipping the pre-emptive unprotect step and proceeding with a best-effort uninstall."
        }

        # Step 2: ALWAYS execute the standard uninstall command.
        # The logic inside Invoke-C9S1StandardUninstall correctly handles adding the '-k' argument only if the passphrase is in the credentials object.
        Write-Host "[$ScriptName] [STANDARD] Executing the standard uninstall method..."
        $uninstallResult = Invoke-C9S1StandardUninstall -CloudCredentials $script:systemState.CloudCredentials -InstallerFile $script:systemState.InstallerFilePath
        
        if (-not $uninstallResult.Success) {
            throw $uninstallResult.Reason
        }
        
        Write-Host -ForegroundColor Green "[$ScriptName] [STANDARD] Standard Uninstall action succeeded."
        $script:systemState.StandardUninstallSucceeded = $true

    } catch {
        Write-Warning "[$ScriptName] [STANDARD] The Standard Uninstall process failed. Reason: $_"
        $script:systemState.StandardUninstallSucceeded = $false
    }
} else {
    # If there's no installer file at all, we must skip this entire phase.
    Write-Warning "[$ScriptName] [STANDARD] SKIPPED: Standard uninstall requires the original installer file path, which was not found in the JSON state file or platform variables."
}

$script:systemState.StandardUninstallAttempted = $true
Write-Host "[$ScriptName] Phase 1 Complete."