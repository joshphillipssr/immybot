$regPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$regName = "PreventLoginWithFailure"

# Retrieve the current registry value
$regObject = Get-WindowsRegistryValue -Path "$regPath" -Name "$regName"

# Evaluate and enforce the desired value
$regObject | RegistryShould-Be -Value 1 -Type DWord