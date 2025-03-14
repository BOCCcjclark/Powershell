# Windows Server Upgrade Script
# This script helps upgrade Windows Server 2008, 2012R2, and 2016 VMs to Windows Server 2022
# Prerequisites: PowerCLI module, administrative access to vCenter, Windows Server 2022 ISO

#region Configuration Parameters
# Update these parameters as needed
$vCenterServer = "your-vcenter-server.domain.com"
#We will need a few ISO paths, one each for the intermediate upgrade steps
# For example, if upgrading from 2008 to 2012R2, then to 2019, and finally to 2022
$iso_path_2008_to_2012 = "path\to\WindowsServer2012.iso"
$iso_path_2012_to_2019 = "path\to\WindowsServer2019.iso"
$iso_path_2019_to_2022 = "path\to\WindowsServer2022.iso"
$backupLocation = "\\your-backup-server\backups"
$logFile = "C:\Logs\ServerUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$upgradeReport = "C:\Logs\UpgradeReport_$(Get-Date -Format 'yyyyMMdd').csv"
#endregion

#region Functions
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Output to console with color coding
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file
    Add-Content -Path $logFile -Value $logMessage
}

function Test-VMUpgradeEligibility {
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )
    
    Write-Log "Checking upgrade eligibility for VM: $($VM.Name)" -Level Info
    
    # Get VM guest OS information
    $guestOS = $VM.Guest.OSFullName
    
    # Check if VM is powered on
    if ($VM.PowerState -ne "PoweredOn") {
        Write-Log "VM $($VM.Name) is not powered on. Power state: $($VM.PowerState)" -Level Warning
        return @{
            Eligible = $false
            Reason = "VM is not powered on"
            UpgradePath = "None"
        }
    }
    
    # Check VM tools status
    if ($VM.Guest.ExtensionData.ToolsStatus -ne "toolsOk") {
        Write-Log "VM $($VM.Name) VMware Tools are not running properly. Status: $($VM.Guest.ExtensionData.ToolsStatus)" -Level Warning
        return @{
            Eligible = $false
            Reason = "VMware Tools are not running properly"
            UpgradePath = "None"
        }
    }
    
    # Check for snapshots
    $snapshots = Get-Snapshot -VM $VM
    if ($snapshots.Count -gt 0) {
        Write-Log "VM $($VM.Name) has $($snapshots.Count) snapshots. Remove them before upgrading." -Level Warning
        return @{
            Eligible = $false
            Reason = "VM has snapshots"
            UpgradePath = "None"
        }
    }
    
    # Determine upgrade path based on guest OS
    if ($guestOS -match "Windows Server 2008") {
        Write-Log "VM $($VM.Name) is running Windows Server 2008. Direct upgrade to 2022 not supported. Intermediate upgrade required." -Level Warning
        return @{
            Eligible = $false
            Reason = "Windows Server 2008 cannot directly upgrade to 2022"
            UpgradePath = "Upgrade to 2012 R2 first, then to 2019, then to 2022"
        }
    }
    elseif ($guestOS -match "Windows Server 2012 R2") {
        Write-Log "VM $($VM.Name) is running Windows Server 2012 R2. Can upgrade to 2022 via 2019." -Level Info
        return @{
            Eligible = $true
            Reason = "Eligible via intermediate upgrade"
            UpgradePath = "Upgrade to 2019 first, then to 2022"
        }
    }
    elseif ($guestOS -match "Windows Server 2016") {
        Write-Log "VM $($VM.Name) is running Windows Server 2016. Direct upgrade to 2022 possible." -Level Info
        return @{
            Eligible = $true
            Reason = "Eligible for direct upgrade"
            UpgradePath = "Direct upgrade to 2022"
        }
    }
    else {
        Write-Log "VM $($VM.Name) OS could not be determined or is not a supported upgrade candidate. Guest OS: $guestOS" -Level Warning
        return @{
            Eligible = $false
            Reason = "Unknown or unsupported OS"
            UpgradePath = "None"
        }
    }
}

function Backup-VMBeforeUpgrade {
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )
    
    $backupName = "$($VM.Name)_Pre2022Upgrade_$(Get-Date -Format 'yyyyMMdd')"
    Write-Log "Creating backup snapshot for VM: $($VM.Name)" -Level Info
    
    try {
        # Create a snapshot
        $snapshot = New-Snapshot -VM $VM -Name $backupName -Description "Pre-Windows Server 2022 upgrade backup" -Quiesce -Memory
        Write-Log "Snapshot created successfully: $($snapshot.Name)" -Level Info
        
        # Export VM configuration
        $vmConfigExport = "$backupLocation\$($VM.Name)_config_$(Get-Date -Format 'yyyyMMdd').xml"
        $VM | Export-Clixml -Path $vmConfigExport
        Write-Log "VM configuration exported to: $vmConfigExport" -Level Info
        
        return $true
    }
    catch {
        Write-Log "Failed to create backup for VM $($VM.Name): $_" -Level Error
        return $false
    }
}

function Mount-UpgradeISO {
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        
        [Parameter(Mandatory=$true)]
        [string]$ISOPath
    )
    
    Write-Log "Mounting Windows Server 2022 ISO to VM: $($VM.Name)" -Level Info
    
    try {
        # Get CD drive
        $cdDrive = Get-CDDrive -VM $VM
        
        # Mount ISO
        Set-CDDrive -CD $cdDrive -ISOPath $ISOPath -Connected $true -Confirm:$false
        Write-Log "ISO mounted successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Failed to mount ISO to VM $($VM.Name): $_" -Level Error
        return $false
    }
}

function Invoke-RemoteUpgrade {
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        
        [Parameter(Mandatory=$true)]
        [string]$UpgradePath
    )
    
    Write-Log "Initiating upgrade process on VM: $($VM.Name)" -Level Info
    
    try {
        # Create credentials for the VM
        $cred = Get-Credential -Message "Enter administrator credentials for $($VM.Name)"
        
        # Establish PowerShell remote session
        $session = New-PSSession -ComputerName $VM.Guest.IPAddress -Credential $cred -ErrorAction Stop
        
        # Execute different commands based on upgrade path
        if ($UpgradePath -eq "Direct upgrade to 2022") {
            Invoke-Command -Session $session -ScriptBlock {
                # Check and install Windows Update prerequisites
                Write-Output "Checking and installing Windows Updates..."
                Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
                Import-Module PSWindowsUpdate
                Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot
                
                # Start Windows Server 2022 setup from mounted ISO
                $setupPath = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }).DriveLetter + ":\setup.exe"
                if (Test-Path $setupPath) {
                    Write-Output "Starting Windows Server 2022 setup..."
                    Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade /quiet /noreboot /compat ignorewarning" -Wait
                    Write-Output "Setup initiated, server will reboot when ready"
                } else {
                    Write-Error "Setup.exe not found on mounted ISO"
                }
            }
        }
        elseif ($UpgradePath -match "Upgrade to 2019 first") {
            Write-Log "Intermediate upgrade to 2019 required. This script will prepare for that step." -Level Info
            Invoke-Command -Session $session -ScriptBlock {
                # Prepare system
                Write-Output "Preparing system for upgrade path to 2019 first, then 2022..."
                
                # System cleanup
                Write-Output "Running system cleanup..."
                Start-Process -FilePath "Cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait
                
                # Check disk
                Write-Output "Checking disk..."
                Start-Process -FilePath "chkdsk.exe" -ArgumentList "/f" -Wait
                
                # Check and install Windows Update prerequisites
                Write-Output "Checking and installing Windows Updates..."
                Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
                Import-Module PSWindowsUpdate
                Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot
                
                Write-Output "System prepared for manual upgrade to 2019"
            }
        }
        else {
            Write-Log "Unsupported upgrade path: $UpgradePath" -Level Error
            return $false
        }
        
        # Close session
        Remove-PSSession -Session $session
        Write-Log "Upgrade process initiated on VM: $($VM.Name)" -Level Info
        return $true
    }
    catch {
        Write-Log "Failed to initiate upgrade on VM $($VM.Name): $_" -Level Error
        return $false
    }
}

function Generate-UpgradeReport {
    param (
        [Parameter(Mandatory=$true)]
        [array]$UpgradeResults
    )
    
    Write-Log "Generating upgrade report" -Level Info
    
    # Export results to CSV
    $UpgradeResults | Export-Csv -Path $upgradeReport -NoTypeInformation
    
    # Create summary
    $summary = @"
Windows Server Upgrade Summary
-----------------------------
Total VMs processed: $($UpgradeResults.Count)
VMs eligible for direct upgrade: $($UpgradeResults | Where-Object { $_.UpgradePath -eq "Direct upgrade to 2022" } | Measure-Object).Count
VMs requiring intermediate upgrade: $($UpgradeResults | Where-Object { $_.UpgradePath -match "Upgrade to 2019 first" } | Measure-Object).Count
VMs not eligible for upgrade: $($UpgradeResults | Where-Object { $_.UpgradePath -eq "None" } | Measure-Object).Count

Upgrade processes initiated: $($UpgradeResults | Where-Object { $_.UpgradeInitiated -eq $true } | Measure-Object).Count
Upgrade processes failed: $($UpgradeResults | Where-Object { $_.UpgradeInitiated -eq $false -and $_.Eligible -eq $true } | Measure-Object).Count

Detailed report saved to: $upgradeReport
"@
    
    Write-Log $summary -Level Info
    return $summary
}
#endregion

#region Main Script
# Create log directory if it doesn't exist
$logDir = Split-Path -Path $logFile -Parent
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

Write-Log "Starting Windows Server upgrade script" -Level Info
Write-Log "Script configuration: vCenter=$vCenterServer, ISO=$iso_path" -Level Info

# Check if PowerCLI module is installed
if (-not (Get-Module -Name VMware.PowerCLI -ListAvailable)) {
    Write-Log "VMware PowerCLI module not found. Installing..." -Level Warning
    Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force
}

# Import PowerCLI module
Import-Module VMware.PowerCLI

# Connect to vCenter
try {
    Write-Log "Connecting to vCenter: $vCenterServer" -Level Info
    Connect-VIServer -Server $vCenterServer -ErrorAction Stop
    Write-Log "Connected to vCenter successfully" -Level Info
}
catch {
    Write-Log "Failed to connect to vCenter: $_" -Level Error
    exit 1
}

# Get Windows Server VMs
Write-Log "Searching for Windows Server VMs" -Level Info
$windowsVMs = Get-VM | Where-Object {
    $_.Guest.OSFullName -match "Windows Server (2008|2012 R2|2016)"
}

Write-Log "Found $($windowsVMs.Count) Windows Server VMs (2008, 2012 R2, or 2016)" -Level Info

# Initialize results array
$upgradeResults = @()

# Process each VM
foreach ($vm in $windowsVMs) {
    Write-Log "Processing VM: $($vm.Name)" -Level Info
    
    # Check eligibility
    $eligibility = Test-VMUpgradeEligibility -VM $vm
    
    $result = [PSCustomObject]@{
        VMName = $vm.Name
        GuestOS = $vm.Guest.OSFullName
        Eligible = $eligibility.Eligible
        Reason = $eligibility.Reason
        UpgradePath = $eligibility.UpgradePath
        BackupCreated = $false
        ISOMounted = $false
        UpgradeInitiated = $false
        Timestamp = Get-Date
    }
    
    # If eligible, continue with preparation
    if ($eligibility.Eligible) {
        # Create backup
        $result.BackupCreated = Backup-VMBeforeUpgrade -VM $vm
        
        if ($result.BackupCreated) {
            # Mount ISO
            $result.ISOMounted = Mount-UpgradeISO -VM $vm -ISOPath $iso_path
            
            if ($result.ISOMounted) {
                # Initiate upgrade
                $result.UpgradeInitiated = Invoke-RemoteUpgrade -VM $vm -UpgradePath $eligibility.UpgradePath
            }
        }
    }
    
    # Add result to array
    $upgradeResults += $result
}

# Generate report
$summary = Generate-UpgradeReport -UpgradeResults $upgradeResults

# Display summary
Write-Host "`n$summary" -ForegroundColor Green

# Disconnect from vCenter
Disconnect-VIServer -Server $vCenterServer -Confirm:$false
Write-Log "Disconnected from vCenter" -Level Info
Write-Log "Script completed" -Level Info
#endregion
