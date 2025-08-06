$value = [int]($InputObject.PreventLoginWithFailure)

if ($value -ne 1) {
    Write-Warning "PreventLoginWithFailure is not set to 1 (actual: $value)"
    return $false
}
return $true