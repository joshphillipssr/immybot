function Is-RDSServerWithFSLogix {
    $isRDS = $Device.Tags -contains "RDS Session Hosts"
    $isWindowsServer = $Device.OperatingSystem -like "*Windows Server*"
    
    $hasFSLogix = $false
    try {
        $svc = Get-Service -Name "frxsvc" -ErrorAction Stop
        $hasFSLogix = $svc.Status -ne $null
    } catch {
        $hasFSLogix = $false
    }

    return ($isRDS -and $isWindowsServer -and $hasFSLogix)
}

if (Is-RDSServerWithFSLogix) {
    Log "Running FSLogix policy enforcement on $($Device.Hostname)"
    Run "FSLogix - Enforce PreventLoginWithFailure"
} else {
    Log "Skipping: Not a qualified FSLogix RDS server ($($Device.Hostname))"
    Skip
}