# Cloud 9 Dynamic Integration Script for SentinelOne

$Integration = New-DynamicIntegration -Init { # Runs every 20 minutes
    param(
        [Parameter(Mandatory)]
        [Uri]$S1Uri,
        [Parameter(Mandatory)]
        [Password(StripValue = $true)]
        $S1ApiKey
    )
    Write-Host "--- [INIT] Script Initializing: $(Get-Date) ---"
    $providerTypeFormData | Write-Variable
    Import-Module SentinelOne
    Get-Command -Module SentinelOne | Out-String | Write-Host
    $S1AuthHeader = Connect-S1API -S1Uri $S1Uri -S1APIToken $S1ApiKey
    
    # Import the module containing our helper functions.
    # Import-Module C9SentinelOne
    
    # Call the refactored Connect function. It will validate credentials and return the auth header on success, or throw on failure.
    # $S1AuthHeader = Connect-C9S1API -S1Uri $S1Uri -S1APIToken $S1ApiKey -Verbose

    # Populate the persistent integration context. This is the ONLY place this should happen.
    $IntegrationContext.S1Uri = $S1Uri
    $IntegrationContext.S1ApiKey = $S1ApiKey
    $IntegrationContext.AuthHeader = $S1AuthHeader

    # Signal success to the ImmyBot platform.
    [OpResult]::Ok()
    
} -HealthCheck { #Runs every minute
    [CmdletBinding()]
    [OutputType([HealthCheckResult])]
    param()
    Write-Host "--- [HEALTHCHECK] Running: $(Get-Date) ---"

    try {
        # This capability must be self-contained.
        Import-Module C9SentinelOne

        Write-Verbose "Performing lightweight health check by calling system/info endpoint..."
        
        # This function will use the pre-authenticated context from -Init.
        # We don't need the result, we just need to know if the call succeeds.
        Invoke-C9S1RestMethod -Endpoint 'system/info' -Verbose -ErrorAction Stop | Out-Null

        Write-Verbose "Health check PASSED. API is responsive."
        return New-HealthyResult
    }
    catch {
        $errorMessage = "Health check FAILED. The API token may be invalid or the service is unreachable. Error: $($_.Exception.Message)"
        Write-Error $errorMessage
        return New-UnhealthyResult -Message $errorMessage
    }
}
# I've started building the new capability here with what I know
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsAuthenticatedDownload 

# Gets list of all tenants from S1 API
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsListingClients -GetClients {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Providers.IProviderClientDetails[]])]
    param()
    Write-Host "--- [GET-CLIENTS] Running: $(Get-Date) ---"
    # Return a list of clients for this integration using the New-IntegrationClient cmdlet
    Import-Module C9SentinelOne
    Get-C9S1Site -Verbose | ForEach-Object {
        if ($_.state -eq "active") {
            New-IntegrationClient -ClientId $_.Id -ClientName $_.Name
        }
    }
}

# Gets list of Agents from S1 API every 30 minutes
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsListingAgents -GetAgents {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Providers.IProviderAgentDetails[]])]
    param(
        [Parameter()]
        [string[]]$clientIds = $null
    )
    Write-Host "--- [GET-AGENTS] Running: $(Get-Date) ---"
    Import-Module C9SentinelOne
    Get-C9S1Agent -Verbose -SiteID $clientIds | ForEach-Object {
        New-IntegrationAgent -Name $_.computerName `
            -SerialNumber $_.serialNumber `
            -OSName $_.osName `
            -Manufacturer $_.modelName `
            -ClientId $_.siteId `
            -AgentId $_.uuid `
            -IsOnline $true `
            -AgentVersion $_.agentVersion `
            -SupportsRunningScripts $false `
            -SupportsOnlineStatus $false
            
    }
}

# This capability allows the integration to provide the site-specific installation token.
$Integration |  Add-DynamicIntegrationCapability -Interface ISupportsTenantInstallToken -GetTenantInstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$clientId
    )
    Import-Module C9SentinelOne
    Get-C9S1Site -Id $clientId | %{ $_.registrationToken}
}

# Deletes an offline agent from S1 API
 $Integration | Add-DynamicIntegrationCapability -Interface ISupportsDeletingOfflineAgent -DeleteAgent {
    [CmdletBinding()]
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory=$true)]
            [Immybot.Backend.Domain.Providers.IProviderAgentDetails]$agent
    )
    Write-Host "--- [DELETE-AGENT] Running: $(Get-Date) ---"

    return "implement me"

}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsDynamicVersions -GetDynamicVersions {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Models.DynamicVersion[]])]
    param(
        [Parameter(Mandatory = $True)]
        [System.String]$ExternalClientId
    )

    # Import our module to make the new function available.
    Import-Module C9SentinelOne

    # Call our new function to get the grouped package data.
    $GroupedPackages = Get-C9S1AvailablePackages

    # Now, process the results and create the DynamicVersion objects.
    foreach ($group in $GroupedPackages.GetEnumerator()) {
        $versionData = $group.Value

        if ($versionData.EXE) {
            # Priority 1: Use the EXE installer.
            New-DynamicVersion -Url $versionData.EXE.link -Version $versionData.Version -FileName $versionData.EXE.fileName -Architecture $versionData.Architecture -PackageType Executable
        }
        elseif ($versionData.MSI) {
            # Priority 2: Fall back to the MSI installer.
            New-DynamicVersion -Url $versionData.MSI.link -Version $versionData.Version -FileName $versionData.MSI.fileName -Architecture $versionData.Architecture -PackageType MSI
        }
    }
}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsTenantUninstallToken -GetTenantUninstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        # This $clientId is the S1 Site ID, provided automatically by the ImmyBot framework.
        [Parameter(Mandatory=$true)]
        [string]$clientId
    )

    # Import our module to make the API functions available.
    Import-Module C9SentinelOne

    # Call the Get-S1Site function to get the full site object from the API.
    $siteObject = Get-S1Site -Id $clientId
    
    # Extract and return the 'passphrase' property from the site object.
    # If the property doesn't exist, this will correctly return $null.
    return $siteObject.passphrase
}

# Capability to provide the uninstall token (passphrase) for a specific AGENT.
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsAgentUninstallToken -GetAgentUninstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        # This $agentId is provided automatically by the ImmyBot framework for the target computer.
        [Parameter(Mandatory=$true)]
        [string]$agentId
    )

    Write-Verbose "GetAgentUninstallToken capability received agentId: $agentId"
    # Import our module to make the new function available.
    Import-Module C9SentinelOne

    # Call our new, dedicated function to get the passphrase for the given Agent ID.
    $passphrase = Get-C9S1AgentPassphrase -AgentId $agentId
    
    # Return the passphrase. ImmyBot will handle providing this to the maintenance script.
    return $passphrase
}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsInventoryIdentification -GetInventoryScript {
    [CmdletBinding()]
    param()
    Invoke-ImmyCommand {
        try {
            $path = Resolve-Path "C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe" -ErrorAction Stop
        } catch {
            Write-Warning "Path not found: $_"
            return
        }

        if (!$path) { return }
        
        . $path.Path agent_id
    }
}

return $Integration
