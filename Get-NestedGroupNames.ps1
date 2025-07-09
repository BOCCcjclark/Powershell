# Recursive Group Scanner with Member Counts
# Lists all nested groups and their member counts

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Get-AllNestedGroupsWithCounts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootGroupName
    )
    
    # Use hashtable to store groups and their member counts
    $groupInfo = @{}
    
    # Queue for groups to process
    $groupsToProcess = New-Object System.Collections.Queue
    $groupsToProcess.Enqueue($RootGroupName)
    
    # Process groups using a queue-based approach
    while ($groupsToProcess.Count -gt 0) {
        $currentGroup = $groupsToProcess.Dequeue()
        
        # Skip if already processed
        if ($groupInfo.ContainsKey($currentGroup)) {
            continue
        }
        
        Write-Host "Processing: $currentGroup" -ForegroundColor Cyan
        
        try {
            # Get all members of current group
            $members = Get-ADGroupMember -Identity $currentGroup -ErrorAction Stop
            
            # Count total members
            $memberCount = $members.Count
            
            # Add group info to our collection
            $groupInfo[$currentGroup] = $memberCount
            
            Write-Host "  Members: $memberCount" -ForegroundColor Gray
            
            # Use foreach to process each member
            foreach ($member in $members) {
                if ($member.objectClass -eq 'group') {
                    # Only add to queue if we haven't seen this group yet
                    if (-not $groupInfo.ContainsKey($member.Name)) {
                        $groupsToProcess.Enqueue($member.Name)
                        Write-Host "  Found nested group: $($member.Name)" -ForegroundColor Yellow
                    }
                }
            }
        }
        catch {
            Write-Warning "Error processing group '$currentGroup': $_"
            $groupInfo[$currentGroup] = -1  # Mark as error
        }
    }
    
    # Convert to array of objects for better output
    $results = foreach ($group in $groupInfo.Keys | Sort-Object) {
        [PSCustomObject]@{
            GroupName = $group
            MemberCount = $groupInfo[$group]
        }
    }
    
    return $results
}

# Alternative recursive approach with foreach and member counts
function Get-NestedGroupsRecursiveWithCounts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$CollectedGroups = @{}
    )
    
    # If we've already collected this group, return immediately
    if ($CollectedGroups.ContainsKey($GroupName)) {
        return
    }
    
    Write-Host "Processing: $GroupName" -ForegroundColor Cyan
    
    try {
        # Get group members
        $members = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
        
        # Count and store
        $memberCount = $members.Count
        $CollectedGroups[$GroupName] = $memberCount
        
        Write-Host "  Members: $memberCount" -ForegroundColor Gray
        
        # Filter to only groups
        $nestedGroups = $members | Where-Object { $_.objectClass -eq 'group' }
        
        # Use foreach to recursively process each nested group
        foreach ($nestedGroup in $nestedGroups) {
            Write-Host "  Found nested group: $($nestedGroup.Name)" -ForegroundColor Yellow
            Get-NestedGroupsRecursiveWithCounts -GroupName $nestedGroup.Name -CollectedGroups $CollectedGroups
        }
    }
    catch {
        Write-Warning "Error processing group '$GroupName': $_"
        $CollectedGroups[$GroupName] = -1  # Mark as error
    }
}

# Main execution examples
Write-Host "`n=== Using Queue-Based Approach ===" -ForegroundColor Green
$groupResults = Get-AllNestedGroupsWithCounts -RootGroupName "RDS General Connectivity"

# Display results in a table
Write-Host "`nGroup Membership Summary:" -ForegroundColor Green
$groupResults | Format-Table -AutoSize

# Store in a variable for further use
$AllGroupsWithCounts = $groupResults

# Alternative: Using recursive approach
Write-Host "`n=== Using Recursive Approach ===" -ForegroundColor Green
$groupCollection = @{}
Get-NestedGroupsRecursiveWithCounts -GroupName "RDS General Connectivity" -CollectedGroups $groupCollection

# Convert to objects for display
$recursiveResults = foreach ($group in $groupCollection.Keys | Sort-Object) {
    [PSCustomObject]@{
        GroupName = $group
        MemberCount = $groupCollection[$group]
    }
}

Write-Host "`nGroup Membership Summary:" -ForegroundColor Green
$recursiveResults | Format-Table -AutoSize

# Export options
# Export to CSV
# $groupResults | Export-Csv -Path "GroupMemberCounts.csv" -NoTypeInformation

# Export to formatted text
# $groupResults | Format-Table -AutoSize | Out-File "GroupMemberCounts.txt"

# Get total unique members across all groups (requires additional processing)
Write-Host "`nTotal groups found: $($groupResults.Count)" -ForegroundColor Cyan
$totalMembers = ($groupResults | Where-Object { $_.MemberCount -ge 0 } | Measure-Object -Property MemberCount -Sum).Sum
Write-Host "Total memberships across all groups: $totalMembers" -ForegroundColor Cyan