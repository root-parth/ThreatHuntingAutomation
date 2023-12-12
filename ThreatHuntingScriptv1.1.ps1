Add-Type -AssemblyName System.Windows.Forms
$table = '$table'

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

$workspacevar = Get-AzOperationalInsightsWorkspace | Select-Object Name, ResourceGroupName
foreach ($workspacedetails in $workspacevar)
{
    $worksacenme = $workspacedetails.Name
    $resorcegrp = $workspacedetails.ResourceGroupName
    Write-Host "`nThe Workspace's name is $worksacenme and it is stored in the resource group $resorcegrp."
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resorcegrp -Name $worksacenme
    $queries = @()
    $foundIOCs = @()
    $notfoundIOCs = @()
    
    Write-Host "Performing Threat Hunting for total of $length IOCs, in the workspace $WSPNME."
    foreach ($item in $IOCsArray) #Generic
    {
	    Write-Host "Searching for the IOC '$item' in the workspace ..."
        $query = "search '$item' | where TimeGenerated > ago(7d) | summarize count() by $table"
        $queries += $query
        $qr = Invoke-AzOperationalInsightsQuery -Workspace $workspace -Query $query
        $jsonobject = ConvertTo-Json $qr.Results
        if ($jsonobject.Length -gt 6)
        {
            Write-Host -ForegroundColor Red "The IOC '$item' was found in the workspace."
            $qr.Results | Format-Table
            Write-Output "`n"
            $foundIOCs += $item
        }
        else
        {   
            $notfoundIOCs += $item
            Write-Host -ForegroundColor Green "The IOC was not found in the workspace.`n"

        }
    }
#Troubleshooting in progress
Write-Host -ForegroundColor Red "`nTotal of '$($foundIOCs.Count)' were found in the log analytics workspace '$worksacenme', Following is the list of those IOCs:`n"
$foundIOCs

Write-Host -ForegroundColor Green "`nTotal of '$($notfoundIOCs.Count)' were NOT found in the log analytics workspace '$worksacenme'.`n"
}

$choice = Read-Host "Do you want to logout? (Y/N)"
# Check the user's choice
if ($choice -eq "Y" -or $choice -eq "y") {
    # Execute the logout command
    Disconnect-AzAccount
    Write-Host "Logged out."
} else {
    # Print a message in red text
    Write-Host -ForegroundColor Red "Please do not forget to logout once the threat-hunting is complete."
}
