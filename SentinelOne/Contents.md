## Contents

Sentinel One.ps1 - Default ImmyBot SentinelOne Dynamic Integration Script
SentinelOne.psm1 - Default ImmyBot SentinelOne PS Module

C9DI-SentinelOne - Cloud 9 Dynamic Integration for SentinelOne
C9DIS-SentinelOne - Cloud 9 Dynamic Integration Script for SentinelOne
C9SentinelOne.psm1 - Cloud 9 SentinelOne PS Module for Metasript Context
C9S1EndpointTools.psm1 - Cloud 9 SentinelOne PS Module for SYSTEM Context

Get-C9S1EndpointData - ImmyBot SentinelOne Task - Get Script

C9HT-SentinelOne - Cloud 9 


# Definitive Installation Context Diagnostic Harness - v2 (ConstrainedLanguage Safe)
# CONTEXT: Metascript (To be run in the "Installation Script" slot of a software package)
#
# PURPOSE: To definitively identify the key name that ImmyBot uses to store the
# installation token within the $ScriptVariables hashtable. This version is hardened
# to work inside PowerShell's ConstrainedLanguage mode.

$VerbosePreference = 'Continue'
Write-Host "--- Installation Context Harness v2 Started ---"

try {
    Write-Host "`n----- Inspecting `$ScriptVariables Hashtable (ConstrainedLanguage Mode) -----"
    
    if ($null -ne $ScriptVariables) {
        Write-Host "[SUCCESS] `$ScriptVariables hashtable was found."
        
        # This is the ConstrainedLanguage-safe way to iterate a hashtable.
        # We access the .Keys property (allowed) instead of calling the .GetEnumerator() method (forbidden).
        Write-Host "--- Dumping all keys and values from `$ScriptVariables ---"
        
        # Step 1: Get the list of keys.
        $keys = $ScriptVariables.Keys

        # Step 2: Loop through the list of keys.
        foreach ($key in $keys) {
            # Step 3: Access the value using the key and print it.
            $value = $ScriptVariables[$key]
            Write-Host ("Key: '{0}', Value: '{1}'" -f $key, $value)
        }
        
        Write-Host "--- End of Dump ---"
        
    } else {
        Write-Error "[FAILURE] The `$ScriptVariables hashtable was NOT found in this context."
    }

} catch {
    $errorMessage = "A fatal error occurred in the diagnostic harness: $($_.Exception.Message)"
    Write-Error $errorMessage
    throw $errorMessage
}

# We still throw an error at the end to prevent the installation from proceeding.
throw "DIAGNOSTIC SCRIPT COMPLETE. This error is expected and prevents a real installation."


Add-DynamicIntegrationCapability:
 231 |  … icIntegrationCapability -Interface ISupportsAgentInstallToken -GetAge …
     |                                       ~~~~~~~~~~~~~~~~~~~~~~~~~~
Line |
     | Cannot validate argument on parameter 'Interface'. The argument "ISupportsAgentInstallToken" does not belong to the set "IProvider,ISupportsListingClients,ISupportsClientGrouping,ISupportsAgentPowerShellInstallScript,ISupportsGetLatestAgentVersion,ISupportsDeletingOfflineAgent,ISupportsHttpRequest,ISupportsListingAgents,ISupportsInventoryIdentification,ISupportsTenantInstallToken,ISupportsTenantUninstallToken,ISupportsAgentUninstallToken,ISupportsMaintenanceMode,ISupportsDynamicVersions,ISupportsDownloadAgentInstaller,ISupportsAuthenticatedDownload,IRunScriptProvider,ISupportsExternalProviderAgentUrl,ISupportsSupportTicketDetailOverride" specified by the ValidateSet attribute. Supply an argument that is in the set and then try the command again.