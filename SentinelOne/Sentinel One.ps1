$Integration = New-DynamicIntegration -Init {
    param(
        [Parameter(Mandatory)]
        [Uri]$S1Uri,
        [Parameter(Mandatory)]
        [Password(StripValue = $true)]
        $S1ApiKey
    )
    $providerTypeFormData | Write-Variable
    Import-Module SentinelOne    
    $S1AuthHeader = Connect-S1API -S1Uri $S1Uri -S1APIToken $S1ApiKey
    $IntegrationContext.S1Uri = $S1Uri
    $IntegrationContext.S1ApiKey = $S1ApiKey
    $IntegrationContext.AuthHeader = $S1AuthHeader
    [OpResult]::Ok()    
} -HealthCheck {
    [CmdletBinding()]
    [OutputType([HealthCheckResult])]
    param()
    # TODO: Implement Health Check
    return New-HealthyResult
}

# Supports listing clients
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsListingClients -GetClients {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Providers.IProviderClientDetails[]])]
    param()
    # Return a list of clients for this integration using the New-IntegrationClient cmdlet
    Import-Module SentinelOne
    Get-S1Site -Verbose | ForEach-Object {
        if ($_.state -eq "active") {
            New-IntegrationClient -ClientId $_.Id -ClientName $_.Name
        }
    }
}

# Supports listing agents
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsListingAgents -GetAgents {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Providers.IProviderAgentDetails[]])]
    param(
        [Parameter()]
        [string[]]$clientIds = $null
    )
    Import-Module SentinelOne
    Get-S1Agent -Verbose -SiteID $clientIds | ForEach-Object {
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


# Supports inventory identification

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

# Supports retrieving a tenant install token
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsTenantInstallToken -GetTenantInstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$clientId
    )
    Import-Module SentinelOne
    Get-S1Site -Id $clientId | %{ $_.registrationToken}
}

# supports retrieving a tenant uninstall token
$Integration |  Add-DynamicIntegrationCapability -Interface ISupportsTenantUninstallToken -GetTenantUninstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [System.String]$clientId
    )
    return "implement me"
}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsDeletingOfflineAgent -DeleteAgent {
    [CmdletBinding()]
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory=$true)]
            [Immybot.Backend.Domain.Providers.IProviderAgentDetails]$agent
    )
    
    return "implement me"

}


return $Integration