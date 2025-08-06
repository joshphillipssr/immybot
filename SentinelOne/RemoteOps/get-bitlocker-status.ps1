<#
.DESCRIPTION
    Get BitLocker Status

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

$filename = 'bitlocker-status' # Default filename for output (without extension)

########################

########################
# Common Settings
########################
$dir = 'C:\ProgramData\Sentinel\RSO' # Default output directory
if ($Env:S1_OUTPUT_DIR_PATH -and (Test-Path -Path $Env:S1_OUTPUT_DIR_PATH)) {
    $dir = $Env:S1_OUTPUT_DIR_PATH
}

Write-Host "Script output directory: $dir"
$DataSetJsonFilePath = 'C:\ProgramData\Sentinel\RSO\dataset.json' # Default dataset.json path
if ($Env:S1_XDR_OUTPUT_FILE_PATH) {
    $DataSetJsonFilePath = $Env:S1_XDR_OUTPUT_FILE_PATH
    New-Item (Split-Path $DataSetJsonFilePath -Parent) -ErrorAction SilentlyContinue -ItemType "directory"
    Write-Host "XDR json output file path: $DataSetJsonFilePath"
}

########################

########################
# Begin Script Function
########################

$scriptfunction = {

    Param (
        # Add parameters specific to script here

        ################
        # remainingargs declared to handle unknown arguments passed, don't remove
        [Parameter(ValueFromRemainingArguments=$true)]$remainingargs #get passed args (not named)
    )

    # Do something, save into an object
    $output = Get-BitLockerVolume | Select-Object -Property * -ExcludeProperty KeyProtector

    # Ensure you write-output of the object so it is passed back to common for formatting and output
    Write-Output $output

}

########################
# End Script Function
########################


##########################
# Begin RSO Script Common
##########################

# !!!!!!!!!!!!!!!!!!
# DO NOT EDIT BELOW
# Common functions for handling script output and calling scriptfunction
$global:outputformat = "csv"

function Invoke-RSOFunction { 
<#
.DESCRIPTION
    Invoke-RSOFunction calls $scriptfunction and then handles output from returned data.
    Creates a file called "dataset.json" for Dataset integration
#>
    Param (
        [Parameter()][string]$format, #format for output, default is csv
        # remainingargs declared to handle unknown arguments passed
        [Parameter(ValueFromRemainingArguments=$true)]$remainingargs #get passed args (not named)
    )
    $global:outputformat = $format

    # Call script function
    $out = & $scriptfunction @Args

    if (-not $out) {
        [System.Collections.ArrayList]$out = @("No Data")
    }

    if ((-not $Env:S1_OUTPUT_DESTINATION) -or ($Env:S1_OUTPUT_DESTINATION -eq "Cloud")) {
        # Output data
        $out | Convert-Data -format $global:outputformat | # Convert To Format
        Export-Data -fullpath $(Join-Path -Path $dir -ChildPath $filename) -format $global:outputformat # Export Data
    }

    if ((-not $Env:S1_OUTPUT_DESTINATION) -or ($Env:S1_OUTPUT_DESTINATION -eq "DataSet")) {
        $out | Convert-Data -format "json" | # Convert To Json Format For Dataset Integration
        Export-Data -fullpath $DataSetJsonFilePath -format "json" -useUTF8 # Export Data
    }
}


function Convert-ObjectDatesToString {
<#
.DESCRIPTION
    Convert-ObjectDatesToString iterates the properties of an object and replaces DateTime fields with a string version.
#>
    Param (
    [Parameter(ValueFromPipeline, Mandatory=$true)]$object
    ) 
    begin {
         $outobject = @()
    }
    process {
        foreach ($obj in $object) {
            $obj = $obj | Select-Object -Property *
            foreach($obj_prop in $obj.PsObject.Properties) {
                if (($obj_prop.Value) -and ($obj_prop.Value).GetType().Name -eq 'DateTime') {
                    $obj.PSObject.Properties.Remove($obj_prop.Name)
                    $obj | Add-Member -Force -MemberType NoteProperty -Name $obj_prop.Name -Value (Get-Date $obj_prop.Value).ToString()
                }       
            }
            $outobject += $obj 
        }    
    }
    end {
        return $outobject
    }
}


function Export-Data { 
<#
.DESCRIPTION
    Export-Data tees output to filepath and console. 
   
.PARAMETER fullpath
    Provide full file path to write data to
.PARAMETER format
    Format of output to decide file extension
#>    
    Param (
    [Parameter(ValueFromPipeline=$true, Mandatory=$true)]$object,
    [Parameter(Mandatory=$true)][string]$fullpath,
    [Parameter()][string]$format,
    [Parameter(Mandatory=$false)][switch]$useUTF8 = $false
    )
   begin {
       $fileext = ".csv"
       switch ($format.ToLower()) {
        json {$fileext = ".json"}
        jsonl {$fileext = ".json"}
        txt {$fileext = ".txt"}
        default {$fileext = ".csv"}
       }
       $inputarray = @()
    }
    process {
        foreach ($obj in $object) {
            $inputarray += $obj
        }
    }
    end {
        $outputFilePath = if ([IO.Path]::GetExtension($fullpath)) { $fullpath } else { "$fullpath$fileext" }
        if ($useUTF8) {
            # Create file with UTF8 Format without BOM, so Set-Content is used instead of Out-File.
            Write-Output $inputarray -NoEnumerate | Set-Content -Path "$outputFilePath"
        } else {
            Write-Output $inputarray -NoEnumerate | Out-File -FilePath "$outputFilePath"
        }
    }
  
}

function Convert-Data { 
<#
.DESCRIPTION
    Convert-Data converts the input object to provided format for output.  
        Convert-ObjectDatesToString is also called to convert dates to string format for better usabilty in json and other formats.

.PARAMETER format
    Provide output format to convert object to
#>    
    Param(
    [Parameter(ValueFromPipeline=$true, Mandatory=$true)]$object,
    [Parameter()][string]$format
    )
    begin {
        $inputarray = @()
    }
    process {
        foreach ($obj in $object) {
            if ($format -eq "txt") {
                $inputarray += $obj
            } else {
                if ($obj.GetType().Name -eq 'String') {
                    $inputarray += ([pscustomobject]@{Output="$obj"})
                } else {
                    $inputarray += ($obj | Convert-ObjectDatesToString)
                }
            }
        }
    }
    end {
        switch ($format.ToLower()) {
            json {
                return ($inputarray | ConvertTo-Json -Compress)
            }
            jsonl {
                $outlines = @()
                foreach ($j in $inputarray) { $outlines += ($j | ConvertTo-Json -Compress) }
                return $outlines
            }
            txt {
                return $($inputarray | Out-String)
            }
            default {
                return ($inputarray | ConvertTo-Csv -NoTypeInformation)
            }
        }
    }
}

# Start the script execution
Invoke-RSOFunction @Args
