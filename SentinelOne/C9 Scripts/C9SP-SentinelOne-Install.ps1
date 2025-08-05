# =================================================================================
# Name:     C9SP-SentinelOne-Install Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

param([string]$rebootPreference)

# $VerbosePreference = 'Continue'
# $ProgressPreference = 'SilentlyContinue'

$tempInstallDir = "C:\Temp\S1_Install_$(Get-Random)"



Import-Module "C9MetascriptHelpers"

Write-Host "[$ScriptName] Before we start, let's see if the endpoint is safe for evasive action..."
$safetyCheck = Test-C9EndpointSafeToReboot -PlatformPolicy $rebootPreference -RequiredIdleMinutes 30 -Verbose

if ($safetyCheck.IsSafe) {
    Write-Host "[$ScriptName] $($safetyCheck.Reason)"
    Write-Host "[$ScriptName] Proceeding with SentinelOne installation..."
    
    Write-Host "[$ScriptName] We'll need some mudules along the way..."
    Import-Module "C9SentinelOneCloud"
    Import-Module "C9SentinelOneMeta"
    Write-Host "[$ScriptName] Modules imported"

    Write-Host "[$ScriptName] We need to do a couple more pre-install checks..."    
    try {
        Write-Host "[$ScriptName] First we'll make sure nothing else is messing around with MSI stuff like Windows Update or some other software routine..."       
        Test-MsiExecMutex
        Write-Host "[$ScriptName] Just us. Second one is to see if there is a pending reboot..."
        if (Test-PendingReboot) {
            Write-Warning "[$ScriptName] A pending reboot was detected. Initiating pre-install reboot..."
            Restart-ComputerAndWait -Force $true -IgnorerebootPreference
            Write-Host "[$ScriptName] And...we're back. The pre-install reboot completed. Now we can continue..."
        } else {
            Write-Host "[$ScriptName] No pending reboot detected..."
        }
        Write-Host "[$ScriptName] Ok. We're done with pre-install checks. Let's get started on the good stuff..."

        Write-Host "[$ScriptName] Staging the MSI installer in a temporary directory..."
        $msiPath = (Join-Path -Path $tempInstallDir -ChildPath "SentinelInstaller.msi").Replace('/','\')
        Invoke-ImmyCommand -ScriptBlock {
            $sourceMsi = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelInstaller.msi").FullName
            if (-not (Test-Path $sourceMsi)) {
                throw "[$using:ScriptName] Source MSI not found at $sourceMsi"
            }
            New-Item -ItemType Directory -Path $using:tempInstallDir -Force | Out-Null
            Copy-Item -Path $sourceMsi -Destination $using:msiPath -Force
        }
        Write-Host "[$ScriptName] Installer staged successfully at: $msiPath"

        Write-Host "[$ScriptName] We're gonna need a Site Token. Let's make an API call to get it..."
        $siteToken = Get-IntegrationAgentInstallToken
        if ([string]::IsNullOrWhiteSpace($siteToken)) {
            throw "[$ScriptName] Did not receive a valid Site Token."
        }
        Write-Host "[$ScriptName] Got the Site Token. Now let's generate a temp log file path..."
        $msiLogFile = Invoke-ImmyCommand {
            [IO.Path]::GetTempFileName()
        }
        Write-Host "[$ScriptName] Generated temporary log file path: $msiLogFile"

        $argumentString = @(
            "/i `"$msiPath`"",
            "/L `"$msiLogFile`"", 
            "/qn",
            "/norestart",
            "SITE_TOKEN=$siteToken",
            "WSC=false"
        ) -join ' '

        try {
            Write-Host "[$ScriptName] Executing the install. There is a high probability that a race condition"
            Write-Host "[$ScriptName] will cause S1 to invoke protection mode before all the S1 Services"
            Write-Host "[$ScriptName] can start, so we're going to kill this install routine in"
            Write-Host "[$ScriptName] 10 minutes if it hasn't already exited. In the mean time"
            Write-Host "[$ScriptName] sit back and relax and watch this log file go nuts for a while."
            $installProcess = Start-ProcessWithLogTail -Path 'msiexec.exe' -ArgumentList $argumentString -LogFilePath $msiLogFile -TimeoutSeconds 600
            
            if ($null -eq $installProcess) {
                throw "[$ScriptName] Start-ProcessWithLogTail did not return a process object."
            }
            $installExitCode = $installProcess.ExitCode
            Write-Host "[$ScriptName] This is a bit shocking...the installer finished cleanly with Exit Code: $installExitCode"
            if ($installExitCode -ne 0 -and $installExitCode -ne 3010) {
                throw "[$ScriptName] Darn it...installer failed with an unexpected error code: $installExitCode. See logs for details."
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*timed out*") {
                Write-Warning "[$ScriptName] Well, as epected, the MSI installer timed out, likely because some S1 Services"
                Write-Warning "[$ScriptName] kept trying to restart over and over and over again."
                Write-Warning "[$ScriptName] This is part of the workaround. We've exited the script cleanly."
            } else {
                throw "[$ScriptName] This sucks. The installer failed with an unexpected, non-timeout (not initiated by us) error: $errorMessage"
            }
        }
        
        Write-Host "[$ScriptName] A post-install reboot is required to finalize the installation. Initiating..."
        try {
            Write-Host "[$ScriptName] Now we're going to reboot so the S1 Services can start up like they're supposed to. Back in a min..."
            Restart-ComputerAndWait -Force $true -IgnorerebootPreference
            Write-Host "[$ScriptName] We're back."
        } catch {
            throw "[$ScriptName] NO!!! Post-install reboot was required, but the self-healing attempt was unsuccessful. Error: $_"
        }

        Write-Host "[$ScriptName] We're back. Let's start some post-install checks..."
        Write-Host "[$ScriptName] Let's check and see if evrything looks good..."
        $s1Info = Get-C9SentinelOneInfo
        if ($s1Info -and $s1Info.IsServiceRunning) {
            Write-Host "[$ScriptName] Success. SentinelOne Agent Service is present and running. Boom."
            Write-Host "[$ScriptName] If we got here, everything worked so we're going to return `$true and get outta here!"
            Write-Host "[$ScriptName] See ya!"
            return $true
        } else {
            throw "[$ScriptName] Final verification failed. The agent service was not found or is not running post-reboot. Bleh."
        }

    } catch {
        $errorMessage = "[$ScriptName] The Installation failed with a fatal error: $($_.Exception.Message)"
        Write-Error $errorMessage
        throw $errorMessage
    } finally {
        if ($null -ne $tempInstallDir) {
            Write-Host "[$ScriptName] Performing final cleanup of temporary directory: $tempInstallDir"
            Invoke-ImmyCommand {
                if (Test-Path $using:tempInstallDir) {
                    Remove-Item -Path $using:tempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
} else {
    Write-Warning "Halting execution. Endpoint is not in a safe state for invasive work."
    Write-Warning "$($safetyCheck.Reason)"
    return $false
}