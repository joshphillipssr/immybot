param($Computer)
if(!$Computer)
{
    $Computer = Get-ImmyComputer
}
$Computer | Invoke-ImmyCommand {
    $ExplorerProcesses = Get-Process Explorer -ErrorAction SilentlyContinue
    if(!$ExplorerProcesses)
    {
        return 'LoggedOut'
    } else
    {
        $LogonUIProcesses = Get-Process LogonUI -ErrorAction SilentlyContinue
        $LogonUIProcessCount = $LogonUIProcesses | measure | select -Expand Count
        if($LogonUIProcessCount -gt 1)
        {
            return 'Locked'
        } else
        {
            return 'Unlocked'
        }
    }
}