# Version: 20250721-01

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
    Import-Module C9SentinelOne
    $S1AuthHeader = Connect-C9S1API -S1Uri $S1Uri -S1APIToken $S1ApiKey -Verbose
    
    $IntegrationContext.S1Uri = $S1Uri
    $IntegrationContext.S1ApiKey = $S1ApiKey
    $IntegrationContext.AuthHeader = $S1AuthHeader

    [OpResult]::Ok()
    
} -HealthCheck { #Runs every minute
    [CmdletBinding()]
    [OutputType([HealthCheckResult])]
    param()
    Write-Host "--- [HEALTHCHECK] Running: $(Get-Date) ---"
    try {
        Import-Module C9SentinelOne
        Write-Verbose "Performing lightweight health check by calling system/info endpoint..."
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

# --- AUTHENTICATED DOWNLOAD CAPABILITY ---
# This is the newly discovered, mandatory capability for authenticated downloads.
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsAuthenticatedDownload -GetAuthHeader {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()

    # This capability's only job is to return the pre-existing authentication header
    # that was created and stored in the -Init block.
    Write-Verbose "C9DI-SentinelOne: -GetAuthHeader capability invoked."
    return $IntegrationContext.AuthHeader
}

# Gets list of all tenants from S1 API
$Integration | Add-DynamicIntegrationCapability -Interface ISupportsListingClients -GetClients {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Providers.IProviderClientDetails[]])]
    param()
    Write-Host "--- [GET-CLIENTS] Running: $(Get-Date) ---"
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
    Get-C9S1Site -Id $clientId | ForEach-Object{ $_.registrationToken}
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
    # return "implement me" # Commenting out placeholder to ensure script validity
}

$Integration | Add-DynamicIntegrationCapability -Interface ISupportsDynamicVersions -GetDynamicVersions {
    [CmdletBinding()]
    [OutputType([Immybot.Backend.Domain.Models.DynamicVersion[]])]
    param(
        [Parameter(Mandatory = $True)]
        [System.String]$ExternalClientId
    )
    Import-Module C9SentinelOne
    $GroupedPackages = Get-C9S1AvailablePackages
    foreach ($group in $GroupedPackages.GetEnumerator()) {
        $versionData = $group.Value
        if ($versionData.EXE) {
            New-DynamicVersion -Url $versionData.EXE.link -Version $versionData.Version -FileName $versionData.EXE.fileName -Architecture $versionData.Architecture -PackageType Executable
        }
        elseif ($versionData.MSI) {
            New-DynamicVersion -Url $versionData.MSI.link -Version $versionData.Version -FileName $versionData.MSI.fileName -Architecture $versionData.Architecture -PackageType MSI
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
    Import-Module C9SentinelOne
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

    # Your harness code adapted for this context
    $report = New-Object -TypeName PSObject
    $VerbosePreference = 'Continue'
    
    try {
        # Phase 1: Environment Info
        $envInfo = New-Object -TypeName PSObject
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'LanguageMode' -Value $ExecutionContext.SessionState.LanguageMode
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'PSVersionTable' -Value $PSVersionTable
        Add-Member -InputObject $envInfo -MemberType NoteProperty -Name 'CurrentLocation' -Value (Get-Location)
        Add-Member -InputObject $report -MemberType NoteProperty -Name 'EnvironmentInfo' -Value $envInfo
        
        # Phase 2: Variable Inspection (most important!)
        $varList = @()
        $allVars = Get-Variable
        foreach ($var in $allVars) {
            $varDetail = New-Object -TypeName PSObject
            Add-Member -InputObject $varDetail -MemberType NoteProperty -Name 'Name' -Value $var.Name
            Add-Member -InputObject $varDetail -MemberType NoteProperty -Name 'Value' -Value ($var.Value | Out-String -Stream)
            $varList += $varDetail
        }
        Add-Member -InputObject $report -MemberType NoteProperty -Name 'AvailableVariables' -Value $varList
        
        # Phase 3: Integration Context
        $contextDetail = New-Object -TypeName PSObject
        if (Get-Variable -Name 'IntegrationContext' -ErrorAction SilentlyContinue) {
            Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name 'Exists' -Value $true
            foreach ($key in $IntegrationContext.Keys) {
                Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name $key -Value $IntegrationContext[$key]
            }
        } else {
            Add-Member -InputObject $contextDetail -MemberType NoteProperty -Name 'Exists' -Value $false
        }
        Add-Member -InputObject $report -MemberType NoteProperty -Name 'IntegrationContext' -Value $contextDetail
        
        # Phase 4: Test if Invoke-ImmyCommand actually works here
        $immyCommandTest = New-Object -TypeName PSObject
        try {
            $result = Invoke-ImmyCommand {
                "I ran on an endpoint at $(Get-Date)"
            }
            Add-Member -InputObject $immyCommandTest -MemberType NoteProperty -Name 'Success' -Value $true
            Add-Member -InputObject $immyCommandTest -MemberType NoteProperty -Name 'Result' -Value $result
        } catch {
            Add-Member -InputObject $immyCommandTest -MemberType NoteProperty -Name 'Success' -Value $false
            Add-Member -InputObject $immyCommandTest -MemberType NoteProperty -Name 'Error' -Value $_.Exception.Message
        }
        Add-Member -InputObject $report -MemberType NoteProperty -Name 'InvokeImmyCommandTest' -Value $immyCommandTest
        
    } catch {
        Add-Member -InputObject $report -MemberType NoteProperty -Name 'FATAL_ERROR' -Value $_.Exception.Message
    }
    
    # Log the harness output for analysis
    Write-Host "=== HARNESS REPORT ==="
    Write-Host ($report | ConvertTo-Json -Depth 10)
    Write-Host "=== END HARNESS ==="

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
