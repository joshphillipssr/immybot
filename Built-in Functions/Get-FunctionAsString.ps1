<#
.SYNOPSIS
    Retrieves the definition of a specified function as a string.

.DESCRIPTION
    This function fetches the script block (definition) of the specified PowerShell function by name and returns it as a string.

.PARAMETER FunctionName
    The name of the function whose definition is to be retrieved.

.INPUTS
    None
    This function does not accept input from the pipeline.

.OUTPUTS
    System.String
    Outputs the definition of the specified function as a single string, including the function's name and script block.

.EXAMPLE
    Get-FunctionAsString -FunctionName "Analyze-Package"
    Retrieves the definition of the Analyze-Package function as a string.
#>

[CmdletBinding()]
param($FunctionName)

$FunctionDefinition = Get-Command $FunctionName -All | ForEach-Object {
    "Function " + $_.Name + "`r`n{`r`n" + (($_.ScriptBlock)) + "`r`n}"
}

New-LiteralString $FunctionDefinition
