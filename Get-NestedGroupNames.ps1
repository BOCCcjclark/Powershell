# Recursive Group Scanner with Member Counts and Export Options
# Lists all nested groups, member counts, and can export member-to-group mappings

Import-Module ActiveDirectory

function Get-AllNestedGroupsWithCounts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootGroupName,
        
        [Parameter(Mandatory=$false)]
        [switch]$ExportMemberMappings,
        
        [Parameter(Mandatory=$false)]
        [string]$ExportPath = "MemberGroupMappings.csv"
    )
    
    # Use hashtable to store groups and their member counts
    $groupInfo = @{}
    
    # Hashtable to store member-to-groups mappings
    $memberToGroups = @{}
    
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
                
                # If ExportMemberMappings is enabled, track all members (not just groups)
                if ($ExportMemberMappings) {
                    $memberKey = "$($member.Name)|$($member.objectClass)|$($member.SamAccountName)"
                    
                    if (-not $memberToGroups.ContainsKey($memberKey)) {
                        $memberToGroups[$memberKey] = New-Object System.Collections.ArrayList
                    }
                    
                    [void]$memberToGroups[$memberKey].Add($currentGroup)
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
    
    # Export member mappings if requested
    if ($ExportMemberMappings) {
        Write-Host "`nPreparing member-to-group mappings for export..." -ForegroundColor Yellow
        
        $memberMappings = foreach ($memberInfo in $memberToGroups.Keys | Sort-Object) {
            $parts = $memberInfo.Split('|')
            $memberName = $parts[0]
            $objectType = $parts[1]
            $samAccountName = $parts[2]
            $groups = $memberToGroups[$memberInfo] | Sort-Object -Unique
            
            [PSCustomObject]@{
                MemberName = $memberName
                SamAccountName = $samAccountName
                ObjectType = $objectType
                GroupCount = $groups.Count
                Groups = ($groups -join '; ')
            }
        }
        
        # Export to CSV
        $memberMappings | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "Member mappings exported to: $ExportPath" -ForegroundColor Green
        Write-Host "Total unique members found: $($memberMappings.Count)" -ForegroundColor Green
        
        # Also return the member mappings
        $global:MemberMappings = $memberMappings
    }
    
    return $results
}

# Enhanced function with detailed member information export
function Get-DetailedMemberGroupMappings {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootGroupName,
        
        [Parameter(Mandatory=$false)]
        [string]$ExportPath = "DetailedMemberMappings.csv",
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeNestedOnly
    )
    
    Write-Host "Collecting all groups starting from: $RootGroupName" -ForegroundColor Green
    
    # First, get all groups
    $allGroups = Get-AllNestedGroupsWithCounts -RootGroupName $RootGroupName
    
    # Collect all unique members with their group memberships
    $allMembers = @{}
    
    foreach ($groupObj in $allGroups) {
        $groupName = $groupObj.GroupName
        
        if ($groupObj.MemberCount -gt 0) {
            Write-Host "Processing members of: $groupName" -ForegroundColor Cyan
            
            try {
                $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                
                foreach ($member in $members) {
                    # Skip groups if we only want users/computers
                    if ($IncludeNestedOnly -and $member.objectClass -eq 'group') {
                        continue
                    }
                    
                    $memberKey = $member.DistinguishedName
                    
                    if (-not $allMembers.ContainsKey($memberKey)) {
                        # Get detailed info about the member
                        try {
                            if ($member.objectClass -eq 'user') {
                                $adObject = Get-ADUser -Identity $member.DistinguishedName -Properties DisplayName, EmailAddress, Department, Title -ErrorAction Stop
                            }
                            elseif ($member.objectClass -eq 'computer') {
                                $adObject = Get-ADComputer -Identity $member.DistinguishedName -Properties Description, OperatingSystem -ErrorAction Stop
                            }
                            else {
                                $adObject = Get-ADGroup -Identity $member.DistinguishedName -Properties Description -ErrorAction Stop
                            }
                            
                            $allMembers[$memberKey] = @{
                                Name = $member.Name
                                SamAccountName = $member.SamAccountName
                                ObjectType = $member.objectClass
                                DisplayName = if ($adObject.DisplayName) { $adObject.DisplayName } else { $member.Name }
                                Email = if ($adObject.EmailAddress) { $adObject.EmailAddress } else { "" }
                                Department = if ($adObject.Department) { $adObject.Department } else { "" }
                                Title = if ($adObject.Title) { $adObject.Title } else { "" }
                                Description = if ($adObject.Description) { $adObject.Description } else { "" }
                                OperatingSystem = if ($adObject.OperatingSystem) { $adObject.OperatingSystem } else { "" }
                                Groups = New-Object System.Collections.ArrayList
                            }
                        }
                        catch {
                            # Fallback if detailed info can't be retrieved
                            $allMembers[$memberKey] = @{
                                Name = $member.Name
                                SamAccountName = $member.SamAccountName
                                ObjectType = $member.objectClass
                                DisplayName = $member.Name
                                Email = ""
                                Department = ""
                                Title = ""
                                Description = ""
                                OperatingSystem = ""
                                Groups = New-Object System.Collections.ArrayList
                            }
                        }
                    }
                    
                    # Add this group to the member's group list
                    [void]$allMembers[$memberKey].Groups.Add($groupName)
                }
            }
            catch {
                Write-Warning "Error processing members of group '$groupName': $_"
            }
        }
    }
    
    # Convert to exportable format
    Write-Host "`nPreparing detailed member report..." -ForegroundColor Yellow
    
    $detailedReport = foreach ($memberDN in $allMembers.Keys | Sort-Object) {
        $member = $allMembers[$memberDN]
        $groups = $member.Groups | Sort-Object -Unique
        
        [PSCustomObject]@{
            Name = $member.Name
            DisplayName = $member.DisplayName
            SamAccountName = $member.SamAccountName
            ObjectType = $member.ObjectType
            Email = $member.Email
            Department = $member.Department
            Title = $member.Title
            Description = $member.Description
            OperatingSystem = $member.OperatingSystem
            GroupCount = $groups.Count
            Groups = ($groups -join '; ')
        }
    }
    
    # Export to CSV
    $detailedReport | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Detailed member report exported to: $ExportPath" -ForegroundColor Green
    Write-Host "Total unique members found: $($detailedReport.Count)" -ForegroundColor Green
    
    # Return the report
    return $detailedReport
}

# # Usage Examples
# Write-Host "`n=== USAGE EXAMPLES ===" -ForegroundColor Magenta

# # Example 1: Basic group listing with counts
# Write-Host "`nExample 1: Basic group listing" -ForegroundColor Yellow
# $groupResults = Get-AllNestedGroupsWithCounts -RootGroupName "Domain Users"
# $groupResults | Format-Table -AutoSize

# # Example 2: Export member mappings
# Write-Host "`nExample 2: Export member-to-group mappings" -ForegroundColor Yellow
# $groupsWithExport = Get-AllNestedGroupsWithCounts -RootGroupName "Domain Users" -ExportMemberMappings -ExportPath "MemberMappings.csv"

# # Example 3: Detailed member report (users and computers only)
# Write-Host "`nExample 3: Detailed member report" -ForegroundColor Yellow
# # $detailedReport = Get-DetailedMemberGroupMappings -RootGroupName "Domain Users" -ExportPath "DetailedMembers.csv" -IncludeNestedOnly

# The member mappings are also available in the global variable
# $global:MemberMappings | Where-Object { $_.ObjectType -eq 'user' } | Select-Object -First 10