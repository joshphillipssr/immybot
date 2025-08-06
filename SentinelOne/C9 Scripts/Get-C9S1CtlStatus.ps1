# This logic is based on the proven detection script pattern.
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAgent'" -ErrorAction SilentlyContinue

        # If the service doesn't exist, the agent is not installed. Return $null.
        if (-not ($service -and $service.PathName)) {
            Write-Warning "SentinelAgent service not found on endpoint. Agent is not installed."
            return $null
        }

        # If the service exists, proceed to gather more details.
        $agentExePath = $service.PathName.Trim('"')
        $installPath = Split-Path -Path $agentExePath
        $sentinelCtlPath = Join-Path -Path $installPath -ChildPath "sentinelctl.exe"

        # Final validation: Ensure the paths reported by the service actually exist.
        if (-not (Test-Path -LiteralPath $agentExePath)) {
            Write-Error "Service found, but its executable path is invalid: $agentExePath"
            return $null
        }

        if (-not (Test-Path -LiteralPath $sentinelCtlPath)) {
            Write-Error "Agent found, but sentinelctl.exe is missing from its directory: $sentinelCtlPath"
            # We can still return info, but log the error. The caller can decide how to handle a missing ctl tool.
        }

        # Get version info from the executable's metadata.
        $fileInfo = Get-Item -LiteralPath $agentExePath
        $version = $fileInfo.VersionInfo.ProductVersion

        # Construct and return the rich object with all collected data.
        return $sentinelCtlPath
        