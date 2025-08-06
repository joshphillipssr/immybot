<#
.DESCRIPTION
    Identity Agent Uninstaller

.NOTES
    Last Edit: 2023-08-28
    version 1.4 - add environment variable to determine output destination
    version 1.3 - align default output path for all scripts including "action"
    version 1.2 - create dataset.json file by default for RSO DataSet integration
    Version 1.1 - update for standardized RSO metadata script template
    Version 1.0 - initial release
#>

########################
# Script Settings
########################

########################

########################
# Common Settings
########################
$dir = 'C:\ProgramData\Sentinel\RSO' # Default output directory
if ($Env:S1_OUTPUT_DIR_PATH -and (Test-Path -Path $Env:S1_OUTPUT_DIR_PATH)) {
    $dir = $Env:S1_OUTPUT_DIR_PATH
}

if (-not $env:S1_PACKAGE_DIR_PATH) { $env:S1_PACKAGE_DIR_PATH = $PSScriptRoot }
Write-Host "Script output directory: $dir"

########################

########################
# Begin Script Function
########################

####################################################################################
#                                                                                  #
# Attivo Networks, Inc.                                                            #
#                                                                                  #
# CONFIDENTIAL                                                                     #
#                                                                                  # 
# Copyright 2014 - 2015 Attivo Networks, Inc.   All Rights Reserved.               #
#                                                                                  #  
# NOTICE: All information contained in this file, is and shall remain the property #
# of Attivo Networks and its suppliers, if any.                                    #
#                                                                                  #
# The intellectual and technical concepts contained herein are confidential and    #
# proprietary to Attivo Networks and are protected by trade secret and copyright   #
# law.  In addition, elements of the technical concepts are patent pending.        #
# This file is part of the Attivo Networks BOTsink Solutions product suite.        # 
# No part of the BOTsink Solutions product suite, including this file, may be used,#
# copied, or modified, except in accordance with the terms contained in the Attivo #
# Networks license agreement under which you obtained this file.  In no case may   #
# you use this software outside of its intended use or distribute this software to # 
# 3rd parties.                                                                     # 
#                                                                                  # 
####################################################################################

<#
    .Synopsis
        Attivo Endpoint agent installer Script        

    .DESCRIPTION
        This script can be used to Install or Uninstall Attivo endpoint agent by providing installtoken collected from BOTSink.
        
    .EXAMPLE
        To install latest version endpoint agent using installtoken generated from` BOTSink.
        .\EPInstaller.ps1 /installtoken <tokenvalue>

        To Enable logging 
        .\EPInstaller.ps1 -Enablelog /installtoken <tokenvalue>

        To Uninstall
        .\EPInstaller.ps1 /installtoken <tokenvalue> /ua

    .INPUTS
        #- For installation/uninstallation of latest agent, the script requires a installtoken value generated from BOTSink.

    .OUTPUTS
        The output of the script is a installation/uninstallation of Attivo agent or it shows if it encounters any errors.
       
#>
param (
[switch] $Enablelog = $false,
[switch] $NoAvCheck = $false,
[switch] $PauseAtThend = $false,
[switch] $DisableWritetoParentFolder = $false
)

$currDir = $PSScriptRoot
$parentDir = (Split-Path (get-item $PSScriptRoot) -Parent)
$exePath = "\\epinstaller.exe"
$exePathnew =""


$EncodedDatax64 = "epinstaller"


$EncodedDatax86 = "epinstaller"


[string] $global:InstalledAvs=""
$global:EnableLogging = $false
$global:InstallParameterFound = $false
$global:UnInstallParameterFound = $false

function Write-LogFileEntry {
    param(
    [Parameter(Mandatory=$True, Position=0)] 
    [string] $Message,
    [string] $ForegroundColor,
    [switch] $IncludeErrorVar,
    [switch] $ClearErrorAfterLogging,
    [switch] $DoNotPrintToScreen = $off
    )

    if (($global:EnableLogging)) {
        if (!(Test-Path $LogFilePath)) {
            new-item $LogFilePath -type file | out-null 
        }
    }

    try {
        if ($DoNotPrintToScreen) {
            #then dont write to screen
        } else {
            if ( $ForegroundColor.Length -gt 1) {
                Write-Host -ForegroundColor $ForegroundColor $Message
            } else {
                Write-Host $Message
            }
        }

        if (($global:EnableLogging)) {
            "$(get-date -Format 'dd/MM/yyyy-hh:mm:ss')::$($Message)" | Out-File $LogFilePath -Append
            if ($IncludeErrorVar) {
                $error | Out-File $LogFilePath -Append        
            }
        }

        if ($ClearErrorAfterLogging) {
            $error.clear()
        }
    } catch {
        Write-Host $Message
    }
}

Function CheckFor3rdPartyAVInstalled {
    try {
        $NameSpace = Get-WmiObject -Namespace "root" -Class "__Namespace" | Select Name | Out-String -Stream | Select-String "SecurityCenter"
        foreach ($SecurityCenter in $NameSpace)  { 
            $AvDisplayName = (Get-WmiObject -Namespace "root\$SecurityCenter" -Class AntiVirusProduct -ErrorAction SilentlyContinue).displayName

            foreach ($AVName in $AvDisplayName)  {
                if ( $AVName -ne $NULL -and $AVName.length -gt 1) {
                    if ($global:InstalledAvs -eq $NULL -or $global:InstalledAvs.length -eq 0) {
                        $global:InstalledAvs = $AVName
                    } else {
                        $global:InstalledAvs =  $global:InstalledAvs + "`n" + $AVName
                    }
                }
            }                
        }
    } catch {
        Write-LogFileEntry "Exception while getting Security product information: Details: $($_.Exception.Message)"
        return
    }        
}

function ExtractEmbedSetupfile {
    param(
        [string] $Setuppath
    )

    $product  = Get-WmiObject -Class Win32_OperatingSystem

    if (($product.OSArchitecture).StartsWith("64")) {
        $Bytes = [System.Convert]::FromBase64String($EncodedDatax64)
    } elseif (($product.OSArchitecture).StartsWith("32")) {
        $Bytes = [System.Convert]::FromBase64String($EncodedDatax86)
    } else {
        return $false
    }
    
    [System.IO.File]::WriteAllBytes($Setuppath, $Bytes)
    
    return $true
}

function GetPackgedSetupfile {
    param(
        [string] $Setuppath
    )

    $product  = Get-WmiObject -Class Win32_OperatingSystem
    $packageDirectory = $Env:S1_PACKAGE_DIR_PATH

    if ((Test-Path $packageDirectory)) {
        if (($product.OSArchitecture).StartsWith("64")) {
            $PkgExtractedPath = "$packageDirectory\EPInstaller\x64\EPInstaller.exe"
        } elseif (($product.OSArchitecture).StartsWith("32")) {
            $PkgExtractedPath = "$packageDirectory\EPInstaller\x86\EPInstaller.exe"
        } else {
            return $false
        }
    } else {
        Write-LogFileEntry "Package Directory not found :$packageDirectory"
        return $false
    }

    if ((Test-Path $PkgExtractedPath)) {
        Copy-Item -Path $PkgExtractedPath  -Destination $Setuppath
    } else {
        Write-LogFileEntry "Epinstaller.exe Package extracted path not found :$PkgExtractedPath"
        return $false
    }

    return $true
}

function VerifyCommandlineParameters {
    param(
        [string] $InParameters
    )
    [bool]$Installtokenfound = $false


    $Values = $InParameters.split(" ")

    for ( $i = 0; $i -lt $Values.Length; $i++ ) {
        #Write-host " Values : $($Values[$i])"
        if (( $Values[$i].ToLower() -cmatch "^/ia$" )) {
            $global:InstallParameterFound = $true
        } elseif (($Values[$i].ToLower() -cmatch "^/ua$" )) {
            $global:UnInstallParameterFound = $true
        } elseif ($Values[$i].ToLower() -cmatch "/installtoken") {
            $Installtokenfound = $true
            $i++
        }
    }

    if ( $Installtokenfound ) {
        return $true
    } else {
        return $false
    }
}

function VerifyDigitalSignatureofdecodedBinary {
    param(
        [string] $ExtrctedExepath
    )

    if ((Test-path $ExtrctedExepath)) {
        if ( (Get-AuthenticodeSignature $ExtrctedExepath).Status -eq "Valid" ) {
            return $true
        }
    }

    return $false
}

Function Execute-Cmd ([string]$CmdTool, [string] $ArgumentsToExecute, [switch] $ReturnStdOut ) {
    $psExitCode = -1
    $OutVar = ""
    Write-LogFileEntry "Execute-Cmd: $CmdTool $ArgumentsToExecute" | Out-Null    
    try {        
        $ps = new-object System.Diagnostics.Process
        $ps.StartInfo.Filename = $CmdTool
        $ps.StartInfo.Arguments = $ArgumentsToExecute
        $ps.StartInfo.RedirectStandardOutput = $True
        $ps.StartInfo.UseShellExecute = $false
        $ps.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $ps.Start() | Out-Null
        [string] $OutVar = $ps.StandardOutput.ReadToEnd();
        $psExitCode = $ps.ExitCode
        Write-LogFileEntry "Execute-Cmd returned Exitcode: $($ps.ExitCode)"  | Out-Null
        Write-LogFileEntry "Output From Command: $OutVar" | Out-Null
    } catch {
        Write-LogFileEntry "Execute-Cmd: Exception when running process. Details: $($_.Exception.Message)"  | Out-Null
    }

    if ($ReturnStdOut) {
        return $OutVar
    }

    return $psExitCode
}
function SpawntheSetup {
    param(
        [string] $ExtrctedExepath,
        [string] $Inputargs
    )
    
    $ExtCode = -1
        
    if ((Test-path $ExtrctedExepath)) {
        $ExtCode = Execute-Cmd -CmdTool $ExtrctedExepath -ArgumentsToExecute $Inputargs

        if ($ExtCode -ne 0) {
            Write-LogFileEntry "Unable to run successfully binary :$ExtrctedExepath"
        } else {
            Write-LogFileEntry "Binary executed successfully path :$ExtrctedExepath"
        }
    } else {
        $ExtCode = 2 #ERROR_FILE_NOT_FOUND
    }
    return $ExtCode
}

function CheckForAVInstalled() {
    if (($NoAvCheck -eq $false) -and ($global:UnInstallParameterFound -eq $false)) {
        Write-LogFileEntry "`n`nChecking for AV/EDR Installations`n"

        CheckFor3rdPartyAVInstalled

        Write-LogFileEntry "Following Endpoint Security product(s) discovered on the endpoint`n"
        Write-LogFileEntry "$InstalledAvs`n"
        Write-LogFileEntry "Please add Attivo Application/files in the above Security Products exclusions. Please refer to Attivo documentation for more details.`n" -ForegroundColor Yellow
    } 
}

function Check-Interactive() {
    return [Environment]::UserInteractive -and !([Environment]::GetCommandLineArgs() |? {$_ -ilike '-NonI*'})
}

function CleanupUnwantedfiles {
    param (
        [switch] $DeleteExeFiles,
        [switch] $DeleteDllFiles,
        [switch] $IgnoretempFolder=$false
    )

    [string[]] $exeFilestoDelete = @("epinstaller.exe")        
    [string[]] $dllFilestoDelete = @("crypto.dll", "libeay32.dll", "libwebsocket.dll","msvcp120.dll","msvcr120.dll", "ssleay32.dll", "libcrypto-3-x64.dll", "libssl-3-x64.dll")

    if ($DeleteExeFiles) {
        foreach ($File in $exeFilestoDelete) {
            if ($DisableWritetoParentFolder) {
                $filetodelete = $currDir + "\\$File"
            } else {
                $filetodelete = $parentDir + "\\$File"
            }
            
            if ((Test-path $filetodelete)) {
                Remove-Item $filetodelete -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }    
    }

    if ($DeleteDllFiles) {
        foreach ($File in $dllFilestoDelete) {
            if ($DisableWritetoParentFolder) {
                $filetodelete = $currDir + "\\$File"
            } else {
                $filetodelete = $parentDir + "\\$File"
            }
            
            if ((Test-path $filetodelete)) {
                Remove-Item $filetodelete -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }    
    }
    #Removing the Download folder
    if ($DisableWritetoParentFolder) {
        $foldertodelete = $currDir + "\\download"
        Remove-Item $foldertodelete -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        if (!$IgnoretempFolder) {
            Remove-Item $currDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        $foldertodelete = $parentDir + "\\download"
        Remove-Item $foldertodelete -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        
        if (!$IgnoretempFolder) {        
            Remove-Item $parentDir -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

if ($Enablelog) {
    $global:EnableLogging = $true
    $LogFilePath = "Epinstaller-$(get-date -Format 'hhmm_dd_MM_yyyy').log"    
}

Write-LogFileEntry "--Started Windows EP Installer Script--"
Write-LogFileEntry "-- Version 5.5M --" # Version number format: Major.Minor
Write-LogFileEntry "-- Build 220610.0 --" # Build number format: YYMMDD

try {
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $newargs =""
        if (Check-Interactive) {
            if ( $Enablelog ) {
                $newargs +=" -Enablelog "
            }
            
            if ( $NoAvCheck ) {
                $newargs +=" -NoAvCheck "
            }
            
            if ($DisableWritetoParentFolder) {
                $newargs +=" -DisableWritetoParentFolder "
            }
            
            $newargs +=" -PauseAtThend "
            
            if ($newargs.Length -gt 1) {
                $retcode = start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; &  `"$PSCommandPath $newargs $args`";`"";
            } else {
                $retcode = start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & `"$PSCommandPath $args`";`"";
            }
            exit $retcode.ExitCode
        } else {
            Write-LogFileEntry "`nRun the script with Administrator privilege`n" -ForegroundColor Yellow
            exit 1314 #ERROR_PRIVILEGE_NOT_HELD
        }
    }

    if (!(VerifyCommandlineParameters $args) ) {
        Write-LogFileEntry "`nMandatory input parametes are missing`n" -ForegroundColor Red 
        exit 87  #ERROR_INVALID_PARAMETER
    }
    
    if ($DisableWritetoParentFolder) {
        $currDir = $currDir + "\\Eptemp"
        if (!(Test-Path $currDir)) {
            New-Item -Path $currDir -ItemType "directory" | Out-Null
        }
        
        if (!(Test-Path $currDir)) {
            Write-LogFileEntry "`nUnable to create Eptemp folder - $currDir`n" -ForegroundColor Red 
            exit 3  #ERROR_PATH_NOT_FOUND
        }
        $exePathnew = $currDir + $exePath
    } else {
        $parentDir = $parentDir + "\\Eptemp"
        if (!(Test-Path $parentDir)) {
            New-Item -Path $parentDir -ItemType "directory" | Out-Null
        }
        
        if (!(Test-Path $parentDir)) {
            Write-LogFileEntry "`nUnable to create Eptemp folder - $parentDir`n" -ForegroundColor Red 
            exit 3  #ERROR_PATH_NOT_FOUND
        }        
        $exePathnew = $parentDir + $exePath
    }    
    
    CheckForAVInstalled

    $product  = Get-WmiObject -Class Win32_OperatingSystem

    if (((($product.OSArchitecture).StartsWith("64")) -and (($EncodedDatax64 -ne $null) -and ($EncodedDatax64.Length -ne 0))) -or ((($product.OSArchitecture).StartsWith("32")) -and (($EncodedDatax86 -ne $null) -and ($EncodedDatax86.Length -ne 0)))) {
        CleanupUnwantedfiles -DeleteExeFiles -DeleteDllFiles -IgnoretempFolder
        if ((GetPackgedSetupfile $exePathnew)) {
            if ((VerifyDigitalSignatureofdecodedBinary $exePathnew) ) {    
                $NewArgs = $args
                if (!$global:InstallParameterFound -and !$global:UnInstallParameterFound ) {
                    $NewArgs = $NewArgs + " /ia /service"
                } elseif ($global:InstallParameterFound) {
                    $NewArgs = $NewArgs + " /service"
                }
            
                $ExtCode = SpawntheSetup $exePathnew $NewArgs
                CleanupUnwantedfiles -DeleteExeFiles -DeleteDllFiles
                exit $ExtCode #return code from extracted mini setup file 
            } else {
                Write-LogFileEntry "`nVerification of digital signature of embeded binary is failed`n" -ForegroundColor Yellow
                exit 0xc0000428 #Windows cannot verify the digital signature for this file
            }
        } else {
            Write-LogFileEntry "`nPackage binary installer is missing`n" -ForegroundColor Red 
            exit 2 #ERROR_FILE_NOT_FOUND
        }
    } else {
        Write-LogFileEntry "`nEmbeded binary installer is missing`n" -ForegroundColor Red 
        exit 2 #ERROR_FILE_NOT_FOUND
    }
    CleanupUnwantedfiles -DeleteExeFiles -DeleteDllFiles
    exit 0 #ERROR_SUCCESS
} catch {
    Write-LogFileEntry "Unexpected Error Details: $($_.Exception.Message)"
    exit 310 #ERROR_INVALID_EXCEPTION_HANDLER
}


########################
# End Script Function
########################
