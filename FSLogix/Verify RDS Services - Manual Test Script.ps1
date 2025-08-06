$services = @(
    "TermService",
    "UserProfileService",
    "Netlogon",
    "W32Time"
)

foreach ($svc in $services) {
    $status = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($null -eq $status) {
        Write-Output "${svc}: Not Found"
    } else {
        Write-Output "${svc}: $($status.Status)"
    }
}
