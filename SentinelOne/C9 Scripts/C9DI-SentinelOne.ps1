# =================================================================================
# Name:     C9DI-SentinelOne Dynamic Integration Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

$Integration = New-DynamicIntegration -Init { # Seems to run about every 20 minutes
    param(
        [Parameter(Mandatory)]
        [Uri]$S1Uri,
        [Parameter(Mandatory)]
        [Password(StripValue = $true)]
        $S1ApiKey
    )

    Write-Host "[Init] Init from C9DI-SentinelOne Script Initializing at (UTC): $(Get-Date)"
    Write-Host "[Init] Before we start, let's make sure we have a URI and ApiKey..."
    Write-Host "[Init] This is our `$S1Uri: $S1Uri"
    Write-Host "[Init] Let's confirm our `$S1ApiKey exists..."
    Write-Host "[Init] Is `$S1ApiKey not `$null?: $($null -ne $S1ApiKey)"
    Write-Host "[Init] Ok...that's enough testing...now we get started by importing the C9SentinelOneCloud module..."
    Import-Module C9SentinelOneCloud
    Write-Host "[Init] Next we authenticate and define a `$S1AuthHeader object using the Connect-C9S1API function..."
    $S1AuthHeader = Connect-C9S1API -S1Uri $S1Uri -S1APIToken $S1ApiKey
    Write-Host "[Init] Now let's populate the `$IntegrationContext object's custom variables..."
    $IntegrationContext.S1Uri = $S1Uri
    Write-Host "[Init] `$IntegrationContext.S1Uri: $IntegrationContext.S1Uri"
    $IntegrationContext.AuthHeader = $S1AuthHeader
    Write-Host "[Init] `IntegrationContext.AuthHeader: $IntegrationContext.AuthHeader"
    Write-Host "[Init] We're all done. Let's finish by printing the result..."
    [OpResult]::Ok()
    
} -HealthCheck { # Seems to run every minute
    [CmdletBinding()]
    [OutputType([HealthCheckResult])]
    param()
    Write-Host "[HealthCheck] C9DI-SentinelOne HealthCheck starting at (UTC): $(Get-Date) ---"
    Write-Host "[HealthCheck] We are going to need a `$S1Uri and `$S1ApiKey for this Healthcheck..."
    Write-Host "[HealthCheck] Our `$S1Uri is: $S1Uri"
    Write-Host "[HealthCheck] Is `$S1ApiKey not `$null?: $($null -ne $S1ApiKey)"

    try {
        Write-Host "[HealthCheck] Now let's import our C9SentinelOneCloud module..."
        Import-Module C9SentinelOneCloud
        Write-Host "[HealthCheck] We're ready to perform the HealthCheck with Invoke-C9S1RestMethod..."
        Write-Host "[HealthCheck] Let's run our test against the 'system/info API endpoint..."
        Invoke-C9S1RestMethod -Endpoint 'system/info' -Verbose -ErrorAction Stop | Out-Null
        Write-Host "[HealthCheck] We're done with the HealthCheck. Here is the result..."
        return New-HealthyResult
    }
    catch {
        $errorMessage = "[HealthCheck] Health check FAILED. Error: $($_.Exception.Message)"
        Write-Error $errorMessage
        return New-UnhealthyResult -Message $errorMessage
    }
}

# --- AUTHENTICATED DOWNLOAD CAPABILITY ---
# This capability allows the native ImmyBot downloader to request the necessary
# authentication headers for a specific URL before it attempts the download...I think.
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsAuthenticatedDownload -GetAuthHeader {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()

    Write-Host "[GetAuthHeader] Capability Invoked. AuthHeader is $($IntegrationContext.AuthHeader)"
    return $IntegrationContext.AuthHeader

}

# Gets list of all tenants from S1 API
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsListingClients -GetClients {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Providers.IProviderClientDetails[]])]
    param()
    Write-Host "--- [GET-CLIENTS] Running: $(Get-Date) ---"
    Import-Module C9SentinelOneCloud
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
    Import-Module C9SentinelOneCloud
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
    # Write-Host "[GetTenantInstallToken] Capability Invoked."
    # Write-Host "[GetTenantInstallToken] Before we start, let's see what custom properties we have in the `$IntegrationContext object..."
    # $IntegrationContext | Format-List *
    Import-Module C9SentinelOneCloud
    Get-C9S1Site -Id $clientId | ForEach-Object{ $_.registrationToken}
}

# Deletes an offline agent from S1 API. Don't have this working yet.
 $Integration | Add-DynamicIntegrationCapability -Interface ISupportsDeletingOfflineAgent -DeleteAgent {
    [CmdletBinding()]
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory=$true)]
            [Immybot.Backend.Domain.Providers.IProviderAgentDetails]$agent
    )
    Write-Host "--- [DELETE-AGENT] Running: $(Get-Date) ---"
    # return "implement me" # Commenting out placeholder to ensure script validity
}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsDynamicVersions -GetDynamicVersions {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Models.DynamicVersion[]])]
    param(
        # We need this one for sure:
        [Parameter(Mandatory = $True)] [System.String]$ExternalClientId
        # Doesn't seem like we need this one:
        #[Parameter(Mandatory = $false)] [System.String]$DisplayVersion
    )
    
    Import-Module C9SentinelOneCloud
    
    Write-Host "[GetDynamicVersions] Capability invoked. Fetching all available GA packages..."
    $AvailablePackages = Get-C9S1AvailablePackages
    if (-not $AvailablePackages) {
        throw "[GetDynamicVersions] Did not receive a list of available packages from the API."
    }
    
    # Process all packages and return them to the platform. Seems the platform engine takes it from there.
    foreach ($group in $AvailablePackages.GetEnumerator()) {
        try {
            $packageData = $group.Value
            if ($packageData.EXE) {
                $package = $packageData.EXE; $packageType = 'Executable'
            } elseif ($packageData.MSI) {
                if ($packageData.Architecture -eq 'ARM64') { continue }
                $package = $packageData.MSI; $packageType = 'MSI'
            } else { continue }
            
            New-DynamicVersion -Url $package.link -Version $package.Version -FileName $package.fileName -Architecture $packageData.Architecture -PackageType $packageType
        } catch {
            Write-Warning "[GetDynamicVersions] Failed to process a package object. Error: $($_.Exception.Message)"
        }
    }
}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsTenantUninstallToken -GetTenantUninstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$clientId
    )
    Import-Module C9SentinelOneCloud
    $siteObject = Get-C9S1Site -Id $clientId
    return $siteObject.passphrase
}

# Capability to provide the uninstall token (passphrase) for a specific AGENT.
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsAgentUninstallToken -GetAgentUninstallToken {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$agentId
    )
    Write-Verbose "GetAgentUninstallToken capability received agentId: $agentId"
    Import-Module C9SentinelOne
    $passphrase = Get-C9S1AgentPassphrase -AgentId $agentId
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
