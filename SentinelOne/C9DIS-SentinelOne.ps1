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
    
    # Import the module containing our helper functions.
    Import-Module C9SentinelOne
    
    # Call the refactored Connect function. It will validate credentials and return the auth header on success, or throw on failure.
    $S1AuthHeader = Connect-C9S1API -S1Uri $S1Uri -S1APIToken $S1ApiKey -Verbose

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


# Somehow run on endpoints. Still trying to figure out how this gets called.
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsInventoryIdentification -GetInventoryScript {
    [CmdletBinding()]
    param()
    Write-Host "--- [GET-INVENTORY / TRIGGER] Queuing inventory script for an endpoint: $(Get-Date) ---"
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

# Gets tenant install token from S1 API
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsTenantInstallToken -GetTenantInstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$clientId
    )
    Write-Host "--- [GET-TENANT-INSTALL-TOKEN] Running: $(Get-Date) ---"
    Import-Module C9SentinelOne
    Get-C9S1Site -Id $clientId | ForEach-Object{ $_.registrationToken}
}

# Gets tenant uninstall token from S1 API
$Integration |  Add-DynamicIntegrationCapability -Interface ISupportsTenantUninstallToken -GetTenantUninstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [System.String]$clientId
    )
    Write-Host "--- [GET-TENANT-UNINSTALL-TOKEN] Running: $(Get-Date) ---"
    return "implement me"
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

return $Integration
