# =================================================================================
# Name:     C9SP-SentinelOne-DownloadInstaller Script
# Author:   Josh Phillips
# Contact:  josh@c9cg.com
# Docs:     https://immydocs.c9cg.com
# =================================================================================

$AuthHeader = Get-IntegrationAuthenticatedDownload
Write-Host "[$ScriptName] Retrieved `$AuthHeader: $AuthHeader"
Write-Host "[$ScriptName] Will now download file from $URL"
Download-File $URL -Headers $AuthHeader -Destination $InstallerFile
Write-Host "[$ScriptName] File downloaded and saved to $InstallerFile"