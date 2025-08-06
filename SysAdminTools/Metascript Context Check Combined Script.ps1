Log "Metascript context check"

if ($null -eq $method) {
    Write-Warning "`$method is null — this is not a Metascript context"
} else {
    Log "`$method is $method"
}