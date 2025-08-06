$regPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$regName = "PreventLoginWithFailure"

New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name $regName -Type DWord -Value 1

Write-Output "PreventLoginWithFailure set to 1"
return $true