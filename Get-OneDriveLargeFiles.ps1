# To use it, save the script as a .ps1 file and run it with the user's email:
# .\Get-OneDriveLargeFiles.ps1 -UserPrincipalName user@example.com


<#
.SYNOPSIS
    Generates a CSV report of files larger than 100MB in a user's OneDrive.
    
.DESCRIPTION
    This script connects to a specific user's OneDrive using Microsoft Graph API
    and generates a CSV report of all files larger than 100MB.
    
.PARAMETER UserPrincipalName
    The email address or UPN of the target user.
    
.PARAMETER OutputPath
    The path where the CSV report will be saved. Default is .\OneDriveLargeFiles.csv.
    
.EXAMPLE
    .\Get-OneDriveLargeFiles.ps1 -UserPrincipalName john.doe@contoso.com
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\OneDriveLargeFiles.csv"
)

# Install and import required modules if not already available
$modules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Files")
foreach ($module in $modules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module module..."
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module $module
}

# Create array to store large files
$largeFiles = @()

try {
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "User.Read.All", "Files.Read.All"
    
    # Get the user
    Write-Host "Looking up user $UserPrincipalName..."
    $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'"
    if (-not $user) {
        throw "User $UserPrincipalName not found"
    }
    
    Write-Host "Found user: $($user.DisplayName)"
    
    # Get the user's OneDrive
    Write-Host "Retrieving OneDrive information..."
    $drive = Get-MgUserDrive -UserId $user.Id
    if (-not $drive) {
        throw "OneDrive not found for user $UserPrincipalName"
    }
    
    Write-Host "Found OneDrive: $($drive.Name)"
    
    # Function to scan a folder for large files
    function Scan-Folder {
        param (
            [Parameter(Mandatory=$true)]
            [string]$FolderId,
            
            [Parameter(Mandatory=$false)]
            [string]$FolderPath = ""
        )
        
        try {
            # Get items in the folder
            $items = Get-MgDriveItem -DriveId $drive.Id -DriveItemId $FolderId -ExpandProperty children
            
            foreach ($item in $items.Children) {
                $itemPath = if ($FolderPath) { "$FolderPath/$($item.Name)" } else { $item.Name }
                
                if ($null -ne $item.Folder) {
                    # This is a folder, scan it recursively
                    Write-Host "Scanning folder: $itemPath" -ForegroundColor Cyan
                    Scan-Folder -FolderId $item.Id -FolderPath $itemPath
                }
                elseif ($null -ne $item.File) {
                    # This is a file, check if it's larger than 100MB
                    if ($item.Size -gt 104857600) { # 100MB in bytes
                        Write-Host "Found large file: $itemPath ($([math]::Round($item.Size / 1MB, 2)) MB)" -ForegroundColor Green
                        
                        $largeFiles += [PSCustomObject]@{
                            FileName = $item.Name
                            FilePath = $itemPath
                            FileSizeMB = [math]::Round($item.Size / 1MB, 2)
                            LastModified = $item.LastModifiedDateTime
                            CreatedDate = $item.CreatedDateTime
                            FileType = [System.IO.Path]::GetExtension($item.Name)
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Error scanning folder $_"
        }
    }
    
    # Start scanning from the root
    Write-Host "Scanning OneDrive for files larger than 100MB..."
    Scan-Folder -FolderId "root"
    
    # Export results to CSV
    if ($largeFiles.Count -gt 0) {
        $largeFiles | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Host "Report generated at $OutputPath with $($largeFiles.Count) files." -ForegroundColor Green
    }
    else {
        Write-Host "No files larger than 100MB found in the user's OneDrive." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    # Disconnect from Microsoft Graph
    Write-Host "Disconnecting from Microsoft Graph..."
    Disconnect-MgGraph | Out-Null
}