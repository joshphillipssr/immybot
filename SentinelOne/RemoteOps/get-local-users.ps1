Skip to Main Content


Global
/

Antigen Security, LLC
/

My Sites
/

Select Site
Marketplace

Help

JP

Find a page
Dashboards
Triage
Alerts
Misconfigurations
Vulnerabilities
Discover
Event Search
Inventory
Graph Explorer
Activities
Automate
RemoteOps
Configure
Detections
Agent Management
Reports
Policy & Settings
RemoteOps
Library
Scheduled Tasks
Pending Executions
The navigation path to the Automation Tasks page is now Agent Management > Agent Tasks.
Go To Agent Tasks
38 Items

20 results

Columns

Select Type

Select OS
table>grid>ariaRowSelect






















Identity Agent Uninstaller
Action
5.5.4.128
SentinelOne
2029585599565743701
Sep 1, 2024 3:04 AM
Jul 20, 2025 5:47 AM
Global
Global


Find File by Drive
Data Collection
1.0.0
SentinelOne
1644054306608205501
Mar 19, 2023 4:42 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Services
Data Collection
1.0.0
SentinelOne
1349752020386450187
Feb 6, 2022 2:16 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Security Event Log
Data Collection
1.0.0
SentinelOne
1164327811062693913
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get USB Media
Data Collection
1.0.0
SentinelOne
1164327808906821653
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Scheduled Tasks
Data Collection
1.0.0
SentinelOne
1164327808479002644
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Event Log
Data Collection
1.0.0
SentinelOne
1164327807858245651
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Local Users
Data Collection
1.0.0
SentinelOne
1164327807212322834
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get BitLocker Status
Data Collection
1.0.0
SentinelOne
1164327806230855696
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Network Connections
Data Collection
1.0.0
SentinelOne
1164327805727539215
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Environment Variables
Data Collection
1.0.0
SentinelOne
1164327805215834126
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Installed Apps
Data Collection
1.0.0
SentinelOne
1164327804200812556
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get Device Drivers
Data Collection
1.0.0
SentinelOne
1164327803823325195
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Process List
Data Collection
1.0.0
SentinelOne
1164327803034796041
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Netstat
Data Collection
1.0.0
SentinelOne
1164327802497925128
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Dirlist
Data Collection
1.0.0
SentinelOne
1164327802078494727
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


System Log
Data Collection
1.0.0
SentinelOne
1164327801474514950
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Bash History
Data Collection
1.0.0
SentinelOne
1164327801004752901
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Get DNS Cache
Data Collection
1.0.0
SentinelOne
1164327800342052868
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global


Available WiFi Networks
Data Collection
1.0.0
SentinelOne
1164327799956176899
May 26, 2021 7:11 AM
Jul 20, 2025 5:47 AM
Global
Global

23
View Script Details

SCRIPT DETAILS
Script name
Get Local Users
Script Type
Data Collection
Os Type
Windows
Script Description
N/A
SCRIPT CONTENT
Attached Script
get-local-users.ps1

View Script Content
Attached ZIP File
N/A
ZIP File Expiration
N/A
SCRIPT SETTINGS
Script Execution Timeout
3600
Input Required
Input is not required
Input instructions
N/A
Input Examples
N/A

Edit Script

Run Script
View Script Content

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
⌄
⌄
⌄
<#
.DESCRIPTION
    Get Local Users

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

$filename = 'local-users' # Default filename for output (without extension)

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
        ################
        # remainingargs declared to handle unknown arguments passed
        [Parameter(ValueFromRemainingArguments=$true)]$remainingargs #get passed args (not named)
    )

    $output = Get-LocalUser | Select-Object Name, Enabled, LastLogon, AccountExpires, PasswordRequired, PasswordLastSet, PasswordExpires, SID, Description
    Write-Output $output

}

########################
# End Script Function

Back to Script Details
