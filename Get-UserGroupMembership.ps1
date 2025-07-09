# Create an array to store the report data
$reportData = @()

# Loop through each member in $members
foreach ($user in $members) {
    try {
        # Get the user object with their group memberships
        $adUser = Get-ADUser -Identity $user -Properties MemberOf, DisplayName -ErrorAction Stop
        
        # Get group names from the Distinguished Names
        $groupNames = @()
        foreach ($groupDN in $adUser.MemberOf) {
            # Extract the group name from the DN
            $groupName = $groupDN -replace '^CN=([^,]+),.*$', '$1'
            $groupNames += $groupName
        }
        
        # Create a custom object for the report
        $userReport = [PSCustomObject]@{
            Username = $adUser.SamAccountName
            DisplayName = $adUser.DisplayName
            GroupCount = $groupNames.Count
            Groups = $groupNames -join '; '
        }
        
        # Add to report data
        $reportData += $userReport
        
        # Display to console
        Write-Host "`nUser: $($adUser.SamAccountName) ($($adUser.DisplayName))" -ForegroundColor Cyan
        Write-Host "Groups ($($groupNames.Count)):" -ForegroundColor Yellow
        $groupNames | ForEach-Object { Write-Host "  - $_" }
        
    }
    catch {
        Write-Host "`nError processing $_" -ForegroundColor Red
        
        # Add error entry to report
        $reportData += [PSCustomObject]@{
            Username = $user
            DisplayName = "ERROR"
            GroupCount = 0
            Groups = "Error: $_"
        }
    }
}

# Export to CSV file
$reportData | Export-Csv -Path "UserMembershipReport.csv" -NoTypeInformation
Write-Host "`nReport exported to UserMembershipReport.csv" -ForegroundColor Green

# Display summary
Write-Host "`nSummary: Processed $($reportData.Count) users" -ForegroundColor Green