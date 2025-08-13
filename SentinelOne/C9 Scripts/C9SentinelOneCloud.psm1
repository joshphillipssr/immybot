# =================================================================================
# Name:     C9SentinelOneCloud Module
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

function Connect-C9S1API {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$S1Uri,
        [Parameter(Mandatory)]
        [string]$S1APIToken
    )

    # Create the authorization header. This is the primary artifact of this function.
    $S1AuthHeader = @{ 'Authorization' = "APIToken $S1ApiToken" }

    # Perform a self-contained API call to validate the credentials and URI.
    # This does not use Invoke-C9S1RestMethod to avoid dependency issues before the context is populated.
    $ValidationEndpoint = "$($S1Uri)web/api/v2.1/system/info"
    try {
        Write-Host "[Connect-C9S1API] Validating credentials against API endpoint: $ValidationEndpoint"
        $SystemInfo = Invoke-RestMethod -Uri $ValidationEndpoint -Headers $S1AuthHeader -Method Get -ErrorAction Stop

        # The S1 API wraps the payload in a 'data' property.
        if ($SystemInfo.data.latestAgentVersion) {
            Write-Host "[Connect-C9S1API] Successfully authenticated to SentinelOne API. Latest Agent Version: $($SystemInfo.data.latestAgentVersion)"
            # On success, return the validated header.
            return $S1AuthHeader
        } else {
            # The call succeeded but the response was not in the expected format.
            throw "Invalid response received from system/info endpoint. Authentication may have failed."
        }
    } catch {
        Write-Error "Failed to connect to SentinelOne API at '$S1Uri'. Please verify the URI and API Key."
        # Re-throw the original exception to provide full details to the caller.
        throw
    }
}

function Invoke-C9S1RestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        [string]$Method,
        [string]$Body,
        [HashTable]$QueryParameters = @{}
    )

    $Endpoint = $Endpoint.TrimStart('/')
    $params = @{}
    $params.ContentType = 'application/json'

    if ($Method) {
        $params.method = $Method
    }

    if ($Body) {
        $params.body = $body
        Write-Host "[Invoke-C9S1RestMethod] ThisBody:`r`n$($params.Body)"
    }

    $AuthHeader = $IntegrationContext.AuthHeader
    $BaseUri = $IntegrationContext.S1Uri
    $Uri = "$($BaseUri)web/api/v2.1/$($Endpoint)"

    # Add a check to ensure the context was passed correctly.
    if (-not ($AuthHeader -and $BaseUri)) {
        throw "[Invoke-C9S1RestMethod] IntegrationContext is not properly initialized. AuthHeader or S1Uri is missing."
    }
    
    try {
        do {
            if ($QueryParameters) {
                Write-Host "[Invoke-C9S1RestMethod] This is the `$QueryParameters value: $($QueryParameters | Out-String)"
                $UriWithQuery = Add-UriQueryParameter -Uri $Uri -Parameter $QueryParameters
                $UriWithQuery = $UriWithQuery.ToString().Replace("+", "%20")
            }
            Write-Host "[Invoke-C9S1RestMethod] This is the `$UriWithQuery value: $UriWithQuery"
            $Results = $null
            Write-Host "[Invoke-C9S1RestMethod] Executing API call to final constructed URI: $UriWithQuery"
            Invoke-RestMethod -Uri $UriWithQuery -Headers $AuthHeader @params -ErrorAction Stop | Tee-Object -Variable Results | Select-Object -Expand data 
            # $Results | Format-List * | Out-String | Write-Host
            
            if ($Results.pagination -and $Results.pagination.nextcursor) {
                $QueryParameters.cursor = $Results.pagination.nextcursor
            }
        } while ($Results.pagination -and $Results.pagination.nextcursor)
    } catch {
        if ($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Error "[Invoke-C9S1RestMethod] Unauthorized when accessing $Uri, please ensure the user associated with the API Key can access this endpoint."
            Write-Error "[Invoke-C9S1RestMethod] Possible reasons for Unauthorized access: API token may have expired, is invalid, or does not have the required permissions."
            Write-Error -Exception $_.Exception -ErrorAction Stop
        } else {
            throw $_ #.Exception.Response
        }
    }
}

function Get-C9S1AuthHeader {
    [CmdletBinding()]
    param()

    # The $IntegrationContext variable is automatically populated by the ImmyBot platform
    # when running a script linked to a dynamic integration.
    if (-not $IntegrationContext) {
        throw "FATAL: Get-C9S1AuthHeader cannot execute. The `$IntegrationContext is not available."
    }

    $AuthHeader = @{
        "Authorization" = "ApiToken $($IntegrationContext.S1ApiToken)"
    }

    return $AuthHeader
}

function Get-C9S1Site {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Id
    )
    
    $Endpoint = "sites"
    
    if ($Id) {
        $Endpoint += "/$id"
        Invoke-C9S1RestMethod -Endpoint $Endpoint
        return
    }

    $QueryParameters = @{}
    $LimitParameter = @{ limit = 100 } # We only have 10 sites. This is fine.

    if ($Name) {
        $QueryParameters['name'] = $Name
    }
    $QueryParameters['state'] = 'active'
    $CombinedParameters = $QueryParameters + $LimitParameter

    # The API response for sites is { "data": { "sites": [...] } }
    # Invoke-C9S1RestMethod already expands 'data', so we just need to expand 'sites'
    $Sites = (Invoke-C9S1RestMethod -Endpoint "sites" -QueryParameters $CombinedParameters).sites
    
    if (-not $Name) {
        # If no name filter, return all active sites, sorted
        return $Sites | Sort-Object name
     } else {
        # If a name filter was used, perform an exact match on the results
        $ExactMatch = $Sites | Where-Object { $_.name.Trim() -eq $Name }
        return $ExactMatch
     }

}

function Get-C9S1Agent {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string[]]$SiteId
    )

    $Endpoint = "agents"
    
    $QueryParameters = @{}
    $LimitParameter = @{ limit = 1000 }

    if ($Name) {
        # Using 'computerName__contains' for a more flexible search
        $QueryParameters['computerName__contains'] = $Name
    }
    if($SiteId){
        # The API expects 'siteIds' (plural) as a comma-separated string
        $QueryParameters['siteIds'] = $SiteId -join ','
    }

    $CombinedParameters = $QueryParameters + $LimitParameter

    # The API returns an array directly when successful, so we don't need to expand 'agents'
    $Agents = Invoke-C9S1RestMethod -Endpoint $Endpoint -QueryParameters $CombinedParameters
    
    if (-not $Name) {
        # If no name filter was specified, return all agents sorted by name
        return $Agents | Sort-Object computerName             
     } else {
        # If a name filter was used, perform an exact match on the results
        $ExactMatch = $Agents | Where-Object { $_.computerName -eq $Name }
        if ($ExactMatch.Count -gt 1) {
            Write-Warning "Found multiple agents with the exact name '$Name'. Returning the first one found."
            return $ExactMatch[0]
        }
        return $ExactMatch
     }
    
}

function Get-C9S1AvailablePackages {
    <#
    .SYNOPSIS
        Fetches all available GA agent packages from the S1 API and prioritizes EXE over MSI.
    .DESCRIPTION
        This function queries the S1 API for all available Windows agent installers, groups them
        by version and architecture, and returns a structured object. It is designed to be called
        by the Dynamic Integration's -GetVersions capability.
    #>
    [CmdletBinding()]
    param()

    $FunctionName = "Get-C9S1AvailablePackages"

    Write-Host "[$ScriptName - $FunctionName] Let's build our `$QueryParameters object..."
    $QueryParameters = @{
        limit          = 50; status = 'ga'; sortBy = 'version'; sortOrder = 'desc';
        osTypes        = 'windows'; fileExtensions = '.exe,.msi'; osArches = '64 bit,32 bit,ARM64'
    }
    Write-Host "[$ScriptName - $FunctionName] Our `$QueryParameters is: $QueryParameters"

    Write-Host "[$ScriptName - $FunctionName] We'll build our `$DownloadLinks object with Invoke-C9S1RestMethod..."
    Write-Host "[$ScriptName - $FunctionName] The API endpoint will be 'update/agent/packages'..."
    $DownloadLinks = Invoke-C9S1RestMethod -Endpoint "update/agent/packages" -QueryParameters $QueryParameters
    Write-Host "[$ScriptName - $FunctionName] Retrieved $($DownloadLinks.Count) package links. Now grouping and prioritizing..."

    # Iterate through the list and group the installers into an [ordered] hashtable $GroupedVersions
    # so we know how to handle cases where both an exe and msi exist for the same version and architecture.
    $GroupedVersions = [ordered]@{}
    foreach ($link in $DownloadLinks) {
        if ($link.fileName -like "storage-agent-installer*") { continue }
        $Version = [Version]$link.Version
        $FileArchitecture = switch ($link.OsArch) {
            '64 bit' { "X64" }
            '32 bit' { "X86" }
            'ARM64'  { 'ARM64' }
            default  { continue }
        }
        $GroupKey = "$Version-$FileArchitecture"
        if (-not $GroupedVersions[$GroupKey]) {
            $GroupedVersions[$GroupKey] = @{ Version = $Version; Architecture = $FileArchitecture; EXE = $null; MSI = $null }
        }
        # exe is default
        if ($link.fileExtension -eq '.exe') { $GroupedVersions[$GroupKey].EXE = $link }
        elseif ($link.fileExtension -eq '.msi') { $GroupedVersions[$GroupKey].MSI = $link }
    }
    
    # Return the fully grouped data for the integration to process.
    return $GroupedVersions
}

function Get-C9S1AgentPassphrase {
    <#
    .SYNOPSIS
        Retrieves the uninstall passphrase for a specific SentinelOne agent using its UUID.
    .DESCRIPTION
        This function calls the /agents/passphrases API endpoint, using the agent's UUID
        as a direct query parameter. This is the most efficient method for retrieving the
        passphrase for a known agent.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # This AgentId is the UUID provided by the ImmyBot framework from the inventory script.
        [Parameter(Mandatory = $true)]
        [string]$AgentId
    )

    try {
        # Construct the query parameters using the agent's UUID.
        $queryParameters = @{
            uuid = $AgentId
        }

        Write-Host "Querying passphrase endpoint with Agent UUID: $AgentId..."
        $response = Invoke-C9S1RestMethod -Endpoint "agents/passphrases" -QueryParameters $queryParameters
        
        # The response is an array inside the 'data' property. We take the first item.
        if ($response -and $response.Count -gt 0) {
            Write-Host "Successfully retrieved passphrase."
            return $response[0].passphrase
        }
    
        Write-Warning "Passphrase endpoint returned no data for UUID: $AgentId"
        return $null

    } catch {
        Write-Error "An error occurred during the passphrase retrieval process: $($_.Exception.Message)"
        throw
    }
}

function Invoke-S1RestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        [string]$Method,
        [string]$Body,
        [HashTable]$QueryParameters = @{}
    )

    $Endpoint = $Endpoint.TrimStart('/')
    $params = @{}
    $params.ContentType = 'application/json'

    if ($Method) {
        $params.method = $Method
    }

    if ($Body) {
        $params.body = $body
        Write-Verbose "ThisBody:`r`n$($params.Body)"
    }

    $AuthHeader = $IntegrationContext.AuthHeader ?? $script:S1AuthHeader
    $BaseUri = $IntegrationContext.S1Uri ?? $script:S1Uri
    $Uri = "$($BaseUri)web/api/v2.1/$($Endpoint)"
    
    try {
        do {
            if ($QueryParameters) {
                Write-Verbose "QueryParameters: $($QueryParameters | Out-String)"
                $UriWithQuery = Add-UriQueryParameter -Uri $Uri -Parameter $QueryParameters
                $UriWithQuery = $UriWithQuery.ToString().Replace("+", "%20")
            }
            Write-Verbose $UriWithQuery
            $Results = $null
            Invoke-RestMethod -Uri $UriWithQuery -Headers $AuthHeader @params -ErrorAction Stop | Tee-Object -Variable Results | Select-Object -Expand data 
            $Results | Format-List * | Out-String | Write-Verbose
            
            if ($Results.pagination -and $Results.pagination.nextcursor) {
                $QueryParameters.cursor = $Results.pagination.nextcursor
            }
        } while ($Results.pagination -and $Results.pagination.nextcursor)
    } catch {
        if ($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Error "Unauthorized when accessing $Uri, please ensure the user associated with the API Key can access this endpoint."
            Write-Error "Possible reasons for Unauthorized access: API token may have expired, is invalid, or does not have the required permissions."
            Write-Error -Exception $_.Exception -ErrorAction Stop
        } else {
            throw $_ #.Exception.Response
        }
    }
}

Export-ModuleMember -Function @(
    "Connect-C9S1API",
    "Invoke-C9S1RestMethod",
    "Get-C9S1AuthHeader",
    "Get-C9S1Site",
    "Get-C9S1Agent",
    "Get-C9S1AvailablePackages",
    "Get-C9S1AgentPassphrase",
    "Invoke-S1RestMethod"
)
