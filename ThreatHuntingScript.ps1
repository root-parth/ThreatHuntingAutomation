Add-Type -AssemblyName System.Windows.Forms
# Create an Open File Dialog
$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$openFileDialog.Title = "Select a CSV File"
$openFileDialog.Filter = "CSV Files (*.csv)|*.csv"
$IOCsArray = @()
# Show the dialog and get the user's choice
$result = $openFileDialog.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $selectedFile = $openFileDialog.FileName
    Write-Output "Selected file: $selectedFile"
    $csvData = Import-Csv -Path $selectedFile
    # Create an array to store the content
    # Add each row's value to the array
    foreach ($row in $csvData) { $IOCsArray += $row.IOCs }
    #Display the array content
    #Write-Output "Array content:"
    #$IOCsArray
} else {
    Write-Output "No file selected."
}
$length=$IOCsArray.Length
$resourceGroup = "" #add the name of the resourcegroup here.
$workspaceName = "" #add the name of the log analytics workspace here.
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name $workspaceName
$AzQueryResult = @()
$queries = @()
$table = '$table'
$foundIOCs = @()
$notfouncIOCs = @()
Write-Host "Performing Threat Hunting for total of '$length' IOCs."
foreach ($item in $IOCsArray) #Generic
{
	Write-Host "Searching for the IOC '$item' in the workspace ..."
	$query = "search '$item' | where TimeGenerated > ago(7d) | summarize count() by $table"
	$queries += $query
	$qr = Invoke-AzOperationalInsightsQuery -Workspace $workspace -Query $query
    $jsonobject = ConvertTo-Json $qr.Results
    if ($jsonobject.Length -gt 6)
    {
        $foundIOCs += $item
        Write-Host -ForegroundColor Red "The IOC '$item' was found in the workspace."
        $qr.Results | Format-Table
        Write-Output "`n"
    }
    else
    {   
        $notfoundIOCs += $item
        Write-Host -ForegroundColor Green "The IOC was not found in the workspace.`n"
    }
	$AzQueryResult += $qr.Results
}

#Troubleshooting in progress
#Write-Host -ForegroundColor Red "Total of '$($foundIOCs.Count)' were found in the log analytics workspace '$workspaceName'.`n"
#Write-Host -ForegroundColor Green "'$($notfoundIOCs.Count)', were not found in the log analytics workspace '$workspaceName'.`n"

$choice = Read-Host "Do you want to logout? (Y/N)"
# Check the user's choice
if ($choice -eq "Y" -or $choice -eq "y") {
    # Execute the logout command
    Disconnect-AzAccount
    Write-Host "Logged out."
} else {
    # Print a message in red bold text
    Write-Host -ForegroundColor Red "Please do not forget to logout once the threat-hunting is complete."
}

#another loop
#serach in (CSL, OCILogs, SDF) "$item" //This works, it has been tested.

#OCILogs, Union_SecurityEvent, SymantecDLP