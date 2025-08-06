# Final Go/No-Go test script.
# This will call our newly-wired integration function.

$ErrorActionPreference = 'Stop'

try {
    Write-Verbose "Attempting to call the correctly-wired Get-S1Agent function..." -Verbose
    
    # We call the function, providing only the parameter it needs from us.
    # ImmyBot will handle injecting ApiKey and SentinelOneUri behind the scenes.
    $agentInfo = Get-S1Agent -ComputerName 'JoshTest-DT'
    
    Write-Verbose "SUCCESS! The call to Get-S1Agent succeeded." -Verbose
    Write-Output "Agent Information for JoshTest-DT:"
    # Convert the successful output to JSON for clean, readable logging.
    $agentInfo | ConvertTo-Json -Depth 5 | Write-Output

}
catch {
    Write-Error "FAILURE: The call to Get-S1Agent FAILED. The specific error is:"
    
    # Dump the full error object to see exactly what went wrong inside the function.
    $_ | ConvertTo-Json -Depth 5 | Write-Output
    
    throw "Forcing a failure to ensure full error details are logged by ImmyBot."
}