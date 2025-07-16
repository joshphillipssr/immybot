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
        Write-Verbose "Validating credentials against endpoint: $ValidationEndpoint"
        $SystemInfo = Invoke-RestMethod -Uri $ValidationEndpoint -Headers $S1AuthHeader -Method Get -ErrorAction Stop

        # The S1 API wraps the payload in a 'data' property.
        if ($SystemInfo.data.latestAgentVersion) {
            Write-Verbose "Successfully authenticated to SentinelOne API. Latest Agent Version: $($SystemInfo.data.latestAgentVersion)"
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
        Write-Verbose "ThisBody:`r`n$($params.Body)"
    }

    # REFACTOR: This function now relies *exclusively* on the IntegrationContext.
    # The legacy fallback to script-scoped variables has been removed.
    $AuthHeader = $IntegrationContext.AuthHeader
    $BaseUri = $IntegrationContext.S1Uri
    $Uri = "$($BaseUri)web/api/v2.1/$($Endpoint)"

    # Add a check to ensure the context was passed correctly.
    if (-not ($AuthHeader -and $BaseUri)) {
        throw "IntegrationContext is not properly initialized. AuthHeader or S1Uri is missing."
    }
    
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
    $LimitParameter = @{ limit = 100 }

    if ($Name) {
        $QueryParameters['name'] = $Name
    }
    $QueryParameters['state'] = 'active'
    $CombinedParameters = $QueryParameters + $LimitParameter

    if (-not $Name) {
        Invoke-C9S1RestMethod -Endpoint $Endpoint -QueryParameters $LimitParameter | Select-Object -Expand sites | Sort-Object name
    } else {
        $Sites = Invoke-C9S1RestMethod -Endpoint $Endpoint -QueryParameters $CombinedParameters | Select-Object -Expand sites
        if (-not $Sites) {
            Write-Progress "No sites matched name: $Name using API filter. Fetching all sites..."
            $Sites = Invoke-C9S1RestMethod -Endpoint $Endpoint -QueryParameters $LimitParameter | Select-Object -Expand sites | Sort-Object name
            $SiteCount = $Sites | Measure-Object | Select-Object -expand Count
            Write-Progress "Found $SiteCount site(s)"
        }
        if ($Agents.PSObject.Properties.Name -contains 'data') {
            return $Agents.data
        } else {
            return $Agents
        }
        $Site = $Sites | Where-Object { $_.name.Trim() -eq $Name } # Potential edge case where the `name` property includes whitespace
        $Site
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
    $LimitParameter = @{ limit = 100 }

    if ($Name) {
        $QueryParameters['name'] = $Name
    }
    if($SiteId){
        $QueryParameters['siteid'] = $SiteId
    }

    $CombinedParameters = $QueryParameters + $LimitParameter

    if (-not $Name) {
        Invoke-C9S1RestMethod -Endpoint $Endpoint -QueryParameters $LimitParameter | Sort-Object computerName             
    } else {
        $QueryParameters.name = $Name
        $Agents = Invoke-C9S1RestMethod -Endpoint $Endpoint -QueryParameters $CombinedParameters
        if (-not $Agents) {
            Write-Progress "No Agents matched name: $Name using API filter. Fetching all Agents..."
            $Agents = Get-C9S1Site
            $AgentCount = $Agents | Measure-Object | Select-Object -expand Count
            Write-Progress "Found $AgentCount agent(s)"
        }
        if ($Agents.PSObject.Properties.Name -contains 'data') {
            return $Agents.data
        } else {
            return $Agents
        }
        $Agent = $Agent | Where-Object { $_.name.Trim() -eq $Name } # Potential edge case where the `name` property includes whitespace
        $Agent = $Agent | Should-HaveOne "SentinelOne Agent matching $Name" -TakeFirst
        $Agent
    }
}

Export-ModuleMember -Function @(
    'Connect-C9S1API',
    'Invoke-C9S1RestMethod',
    'Get-C9S1Site',
    'Get-C9S1Agent'
)
