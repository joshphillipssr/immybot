function Connect-S1API {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Uri]$S1Uri,
        [Parameter(Mandatory)]
        [string]$S1APIToken
    )

    $S1AuthHeader = @{ 'Authorization' = "APIToken $S1ApiToken" }

    # if we have an integration context, then store it
    if ($null -ne $IntegrationContext) {
        $IntegrationContext.AuthHeader = $S1AuthHeader
    }

    $script:S1AuthHeader = $S1AuthHeader
    $script:S1Uri = $S1Uri
    [Uri]$script:S1Uri = $S1Uri
    
    try {
        $SystemInfo = Invoke-S1RestMethod -Endpoint 'system/info'
        if ($SystemInfo.latestAgentVersion -like "*.*") {
            Write-Progress "Authenticated to SentinelOne API and retrieved system/info. LatestAgentVersion: $($SystemInfo.LatestAgentVersion)"
            $script:S1AuthHeader
        } else {
            $script:S1AuthHeader = $null
            throw "Invalid response from system/info API"
        }
        Write-Verbose "SystemInfo:`r`n$($SystemInfo | Format-List * | Out-String)"
    } catch {
        $script:S1AuthHeader = $null
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

function Get-S1Site {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Id
    )
    
    $Endpoint = "sites"
    
    if ($Id) {
        $Endpoint += "/$id"
        Invoke-S1RestMethod -Endpoint $Endpoint
        return
    }

    $QueryParameters = @{}
    $LimitParameter = @{ limit = 100 }

    if ($Name) {
        $QueryParameters['name'] = $Name
    }
    $QueryParameters['state'] = 'active'
    $CombinedParameters = $QueryParameters + $LimitParameter

    if (-not $Name) {
        Invoke-S1RestMethod -Endpoint $Endpoint -QueryParameters $LimitParameter | Select-Object -Expand sites | Sort-Object name
    } else {
        $Sites = Invoke-S1RestMethod -Endpoint $Endpoint -QueryParameters $CombinedParameters | Select-Object -Expand sites
        if (-not $Sites) {
            Write-Progress "No sites matched name: $Name using API filter. Fetching all sites..."
            $Sites = Invoke-S1RestMethod -Endpoint $Endpoint -QueryParameters $LimitParameter | Select-Object -Expand sites | Sort-Object name
            $SiteCount = $Sites | Measure-Object | Select-Object -expand Count
            Write-Progress "Found $SiteCount site(s)"
        }
        $Sites | Select-Object id, name, isDefault, registrationToken | Out-String | Write-Verbose
        $Site = $Sites | Where-Object { $_.name.Trim() -eq $Name } # Potential edge case where the `name` property includes whitespace
        $Site
    }
}

function Get-S1Agent {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string[]]$SiteId
    )

    $Endpoint = "agents"
    
    $QueryParameters = @{}
    $LimitParameter = @{ limit = 100 }

    if ($Name) {
        $QueryParameters['name'] = $Name
    }
    if($SiteId){
        $QueryParameters['siteid'] = $SiteId
    }

    $CombinedParameters = $QueryParameters + $LimitParameter

    if (-not $Name) {
        Invoke-S1RestMethod -Endpoint $Endpoint -QueryParameters $LimitParameter | Sort-Object computerName             
    } else {
        $QueryParameters.name = $Name
        $Agents = Invoke-S1RestMethod -Endpoint $Endpoint -QueryParameters $CombinedParameters
        if (-not $Agents) {
            Write-Progress "No Agents matched name: $Name using API filter. Fetching all Agents..."
            $Agents = Get-S1Site
            $AgentCount = $Agents | Measure-Object | Select-Object -expand Count
            Write-Progress "Found $AgentCount agent(s)"
        }
        $Agents | Select-Object id, name, isDefault, registrationToken | Out-String | Write-Verbose
        $Agent = $Agent | Where-Object { $_.name.Trim() -eq $Name } # Potential edge case where the `name` property includes whitespace
        $Agent = $Agent | Should-HaveOne "SentinelOne Agent matching $Name" -TakeFirst
        $Agent
    }
}

Export-ModuleMember -Function @(
    'Connect-S1API',
    'Invoke-S1RestMethod',
    'Get-S1Site',
    'Get-S1Agent'
)
