# =================================================================================
# Name:     C9SP-SentinelOne-Uninstall Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================
$VerbosePreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$tempUninstallDir = $null

Import-Module "C9MetascriptHelpers"

# Write-Host "[$ScriptName] Before we start, let's see if the endpoint is safe for invasive action..."
# $safetyCheck = Test-C9EndpointSafeToReboot -PlatformPolicy $RebootPreference -RequiredIdleMinutes 30 -Verbose

# if ($safetyCheck.IsSafe) {
#     Write-Host "[$ScriptName] $($safetyCheck.Reason)"
#     Write-Host "[$ScriptName] Proceeding with SentinelOne uninstallation..."

    try {
        Write-Host "[$ScriptName] Uninstall Playbook Started..."

        Write-Host "[$ScriptName] Checking for uninstall trigger file..."
        $triggerFileDir = "C:\ProgramData\ImmyBot\S1"; $triggerFileName = "s1_is_null.txt"; $newFileName = "s1_isnot_null.txt"
        Invoke-ImmyCommand {
            $triggerFilePath = Join-Path -Path $using:triggerFileDir -ChildPath $using:triggerFileName
            if (Test-Path $triggerFilePath) {
                Write-Host "[$ScriptName] Found uninstall trigger file. Renaming it to break loop."
                try { Rename-Item -Path $triggerFilePath -NewName $using:newFileName -ErrorAction Stop } catch { Write-Warning "Could not rename trigger file." }
            }
        }
        
        Write-Host "[$ScriptName] We need to grab some modules..."
        Import-Module "C9SentinelOneMeta"
        Import-Module "C9SentinelOneCloud"
        Write-Host "[$ScriptName] Modules imported."

        $Passphrase = $null
        $siteToken = $null

        try {
            Write-Host "[$ScriptName] Attempting to retrieve agent passphrase..."
            $Passphrase = Get-IntegrationAgentUninstallToken -ErrorAction Stop
            Write-Host "[$ScriptName] Passphrase retrieved successfully."
        } catch {
            Write-Warning "[$ScriptName] Could not retrieve agent passphrase. This is expected for an orphaned agent."
        }

        try {
            Write-Host "[$ScriptName] Attempting to retrieve site token..."
            $siteToken = Get-IntegrationAgentInstallToken -ErrorAction Stop
            Write-Host "[$ScriptName] Site token retrieved successfully."
        } catch {
            Write-Warning "[$ScriptName] Could not retrieve site token. The cleaner command may fail."
        }

        Write-Host "[$ScriptName] Running inlined pre-flight checks..."
        try { Test-MsiExecMutex -ErrorAction Stop; Write-Host "[$ScriptName] [PASS] MSI Mutex is available." } catch { throw "Pre-flight check failed: MSI installation in progress." }
        if (Test-PendingReboot) {
            Write-Warning "[$ScriptName] A pending reboot was detected. This must be cleared before proceeding."
            Write-Host "[$ScriptName] Attempting mandatory pre-flight reboot..."
            try { Restart-ComputerAndWait -TimeoutDuration (New-TimeSpan -Minutes 15); Write-Host "[$ScriptName] SUCCESS: The pre-flight reboot completed." } catch { throw "FATAL: Pre-flight reboot was required, but the self-healing attempt was unsuccessful. Error: $_" }
        } else {
            Write-Host "[$ScriptName] No pending reboot detected."
        }
        Write-Host "[$ScriptName] Pre-flight checks complete."

        if ($Passphrase) {
            Write-Host "[$ScriptName] Passphrase found. Attempting best-effort unprotect..."
            try {
                $s1Info = Get-C9SentinelOneInfo
                if ($s1Info.InstallPath) {
                    Set-C9SentinelOneUnprotect -Passphrase $Passphrase -ErrorAction Stop
                    Write-Host "[$ScriptName] Self-protection disabled successfully."
                } else {
                    Write-Warning "[$ScriptName] sentinelctl.exe not found. Skipping unprotect."
                }
            } catch {
                Write-Warning "[$ScriptName] Failed to disable self-protection. This may be okay. Continuing... Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "[$ScriptName] No passphrase found. Skipping unprotect step."
        }
        
        if ($siteToken) {
            Write-Host "[$ScriptName] Site token found. Proceeding to cleaner..."
    
            $exitCodeFile = "C:\Windows\Temp\s1_uninstall_exit_code.txt"
            $tempUninstallDir = Invoke-ImmyCommand -Timeout 1200 -ScriptBlock {
                try {
                    if (Test-Path $using:exitCodeFile) { Remove-Item $using:exitCodeFile -Force }
                    $source = (Get-Item "C:\ProgramData\ImmyBot\S1\Installer\SentinelOneInstaller*.exe").FullName
                    $tempDir = "C:\Temp\S1_Uninstall_$(Get-Date -f yyyyMMdd-hhmmss)"
                    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                    $destination = Join-Path -Path $tempDir -ChildPath (Split-Path $source -Leaf)
                    Copy-Item -Path $source -Destination $destination -Force
                    $cleanerArgs = "-c -q -t `"$($using:siteToken)`""
                    $InstallProcess = Start-Process -NoNewWindow -PassThru -Wait -FilePath $destination -ArgumentList $cleanerArgs
                    Write-Host "[$ScriptName] Cleaner process finished. ExitCode = $($installProcess.ExitCode)"
                    $LASTEXITCODE | Out-File -FilePath $using:exitCodeFile -Encoding ascii
                    return $tempDir
                } catch {
                    "-999" | Out-File -FilePath $using:exitCodeFile -Encoding ascii
                    throw
                }
            }
            $cleanerExitCode = Invoke-ImmyCommand { if (Test-Path $using:exitCodeFile) { Get-Content $using:exitCodeFile } else { return -1 } }
            Write-Host "[$ScriptName] Cleaner process finished with Exit Code: $cleanerExitCode or $($installProcess.ExitCode)"
        } else {
            Write-Warning "[$ScriptName] SKIPPED: The modern cleaner method requires a site token. This is expected for orphaned agents."
        }
        
        Write-Host "[$ScriptName] Uninstallation Playbook Completed Successfully."
        return $true

    } catch {
        $errorMessage = "[C9SP-SentinelOne-Uninstall] The Uninstallation Playbook failed with a fatal error: $($_.Exception.Message)"
        Write-Error $errorMessage
        throw $errorMessage

    }

# } else {
#     Write-Warning "[$ScriptName] Halting execution. Endpoint is not in a safe state for invasive work."
#     Write-Warning "[$ScriptName] Reason: $($safetyCheck.Reason)"
#    return $false
#}