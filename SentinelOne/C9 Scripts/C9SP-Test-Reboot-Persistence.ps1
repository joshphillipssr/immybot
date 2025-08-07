# =================================================================================
# Name:     C9SP-Test-Reboot-Persistence
# Purpose:  A minimal script to empirically test Metascript variable persistence
#           across a Restart-ComputerAndWait cycle.
# =================================================================================

# Use the script: scope for the variable, as this has the best theoretical chance of surviving.
# This block runs when the script is initiated for the first time.
if ($null -eq $script:MyTestVariable) {
    Write-Host -ForegroundColor Yellow "[$ScriptName] PRE-REBOOT: The variable `$script:MyTestVariable was not found. This is expected on the first run."
    
    # Set the variable's value BEFORE the reboot.
    $script:MyTestVariable = "Value-Set-Before-Reboot"
    Write-Host "[$ScriptName] PRE-REBOOT: Variable has been set to: '$($script:MyTestVariable)'"
    
    # Initiate the reboot using the native platform function.
    Write-Host "[$ScriptName] PRE-REBOOT: Initiating the reboot now..."
    Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15)

    # The script execution should effectively pause here until after the reboot.
    # The ImmyBot agent will signal the platform to resume the Maintenance Session.
    # The platform will then re-run this script from the beginning.
}
# This block will execute when the script is re-run by the platform after the reboot.
else {
    Write-Host -ForegroundColor Green "[$ScriptName] POST-REBOOT: SCRIPT EXECUTION RESUMED."
    Write-Host -ForegroundColor Green "[$ScriptName] SUCCESS! The variable `$script:MyTestVariable was preserved across the reboot."
    Write-Host -ForegroundColor Green "[$ScriptName] Its value is: '$($script:MyTestVariable)'"
}