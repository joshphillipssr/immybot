$regPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$regName = "PreventLoginWithFailure"

if (-not (Test-Path $regPath)) {
    return @{ PreventLoginWithFailure = $null }
}

try {
    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    return @{ PreventLoginWithFailure = $value.$regName }
} catch {
    return @{ PreventLoginWithFailure = $null }
}