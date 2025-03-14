# Windows Server Upgrade Script
# This script helps upgrade Windows Server 2003, 2008, 2008 R2, 2012, 2012R2, 2016, and 2019 VMs to Windows Server 2022
# Prerequisites: PowerCLI module, administrative access to vCenter, Windows Server ISOs for intermediate upgrades

#region Configuration Parameters
# Update these parameters as needed
$vCenterServer = "your-vcenter-server.domain.com"

# ISO paths for different Windows Server versions
$isoPathCollection = @{
    "2008" = "path\to\WindowsServer2008R2.iso"
    "2012" = "path\to\WindowsServer2012R2.iso"
    "2016" = "path\to\WindowsServer2016.iso"
    "2019" = "path\to\WindowsServer2019.iso"
    "2022" = "path\to\WindowsServer2022.iso"
}

# Backup and log locations
$backupLocation = "\\your-backup-server\backups"
$logFile = "C:\Logs\ServerUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$upgradeReport = "C:\Logs\UpgradeReport_$(Get-Date -Format 'yyyyMMdd').csv"

# Credentials store - for batch processing
$credentialStore = @{}

# Maximum number of concurrent upgrades (adjust based on your environment capacity)
$maxConcurrentUpgrades = 5

# Wait time in minutes between upgrade status checks
$statusCheckInterval = 15
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
            UpgradeSteps = @()
            RequiredISOs = @()
        }
    }
    
    # Check VM tools status
    if ($VM.Guest.ExtensionData.ToolsStatus -ne "toolsOk") {
        Write-Log "VM $($VM.Name) VMware Tools are not running properly. Status: $($VM.Guest.ExtensionData.ToolsStatus)" -Level Warning
        return @{
            Eligible = $false
            Reason = "VMware Tools are not running properly"
            UpgradePath = "None"
            UpgradeSteps = @()
            RequiredISOs = @()
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
            UpgradeSteps = @()
            RequiredISOs = @()
        }
    }
    
    # Check system resources
    $vmView = $VM | Get-View
    $diskSpaceGB = ($vmView.Guest.Disk | Measure-Object -Property FreeSpace -Sum).Sum / 1GB
    $memoryGB = $VM.MemoryGB
    
    if ($diskSpaceGB -lt 10) {
        Write-Log "VM $($VM.Name) has insufficient free disk space: $([math]::Round($diskSpaceGB, 2)) GB" -Level Warning
        return @{
            Eligible = $false
            Reason = "Insufficient free disk space (minimum 10GB required)"
            UpgradePath = "None"
            UpgradeSteps = @()
            RequiredISOs = @()
        }
    }
    
    if ($memoryGB -lt 2) {
        Write-Log "VM $($VM.Name) has insufficient memory: $memoryGB GB" -Level Warning
        return @{
            Eligible = $false
            Reason = "Insufficient memory (minimum 2GB required)"
            UpgradePath = "None"
            UpgradeSteps = @()
            RequiredISOs = @()
        }
    }
    
    # Determine upgrade path based on guest OS
    # Define the major upgrade paths and required ISOs
    
    # Windows Server 2003/2003 R2
    if ($guestOS -match "Windows Server 2003") {
        Write-Log "VM $($VM.Name) is running Windows Server 2003. Multiple step upgrade required." -Level Warning
        return @{
            Eligible = $true
            Reason = "Multiple step upgrades required"
            UpgradePath = "Multi-step upgrade: 2003 → 2008 R2 → 2012 R2 → 2019 → 2022"
            UpgradeSteps = @("2008", "2012", "2019", "2022")
            RequiredISOs = @("2008", "2012", "2019", "2022")
            CurrentStep = "2003"
            NextStep = "2008"
        }
    }
    # Windows Server 2008 (Non-R2)
    elseif ($guestOS -match "Windows Server 2008" -and $guestOS -notmatch "R2") {
        Write-Log "VM $($VM.Name) is running Windows Server 2008 (non-R2). Multiple step upgrade required." -Level Warning
        return @{
            Eligible = $true
            Reason = "Multiple step upgrades required"
            UpgradePath = "Multi-step upgrade: 2008 → 2012 R2 → 2019 → 2022"
            UpgradeSteps = @("2012", "2019", "2022")
            RequiredISOs = @("2012", "2019", "2022")
            CurrentStep = "2008"
            NextStep = "2012"
        }
    }
    # Windows Server 2008 R2
    elseif ($guestOS -match "Windows Server 2008 R2") {
        Write-Log "VM $($VM.Name) is running Windows Server 2008 R2. Multiple step upgrade required." -Level Warning
        return @{
            Eligible = $true
            Reason = "Multiple step upgrades required"
            UpgradePath = "Multi-step upgrade: 2008 R2 → 2012 R2 → 2019 → 2022"
            UpgradeSteps = @("2012", "2019", "2022")
            RequiredISOs = @("2012", "2019", "2022")
            CurrentStep = "2008"
            NextStep = "2012"
        }
    }
    # Windows Server 2012 (Non-R2)
    elseif ($guestOS -match "Windows Server 2012" -and $guestOS -notmatch "R2") {
        Write-Log "VM $($VM.Name) is running Windows Server 2012 (non-R2). Multiple step upgrade required." -Level Info
        return @{
            Eligible = $true
            Reason = "Multiple step upgrades required"
            UpgradePath = "Multi-step upgrade: 2012 → 2012 R2 → 2019 → 2022"
            UpgradeSteps = @("2012", "2019", "2022")
            RequiredISOs = @("2012", "2019", "2022")
            CurrentStep = "2012"
            NextStep = "2012"
        }
    }
    # Windows Server 2012 R2
    elseif ($guestOS -match "Windows Server 2012 R2") {
        Write-Log "VM $($VM.Name) is running Windows Server 2012 R2. Can upgrade to 2022 via 2019." -Level Info
        return @{
            Eligible = $true
            Reason = "Two-step upgrade required"
            UpgradePath = "Two-step upgrade: 2012 R2 → 2019 → 2022"
            UpgradeSteps = @("2019", "2022")
            RequiredISOs = @("2019", "2022")
            CurrentStep = "2012"
            NextStep = "2019"
        }
    }
    # Windows Server 2016
    elseif ($guestOS -match "Windows Server 2016") {
        Write-Log "VM $($VM.Name) is running Windows Server 2016. Direct upgrade to 2022 possible." -Level Info
        return @{
            Eligible = $true
            Reason = "Eligible for direct upgrade"
            UpgradePath = "Direct upgrade: 2016 → 2022"
            UpgradeSteps = @("2022")
            RequiredISOs = @("2022")
            CurrentStep = "2016"
            NextStep = "2022"
        }
    }
    # Windows Server 2019
    elseif ($guestOS -match "Windows Server 2019") {
        Write-Log "VM $($VM.Name) is running Windows Server 2019. Direct upgrade to 2022 possible." -Level Info
        return @{
            Eligible = $true
            Reason = "Eligible for direct upgrade"
            UpgradePath = "Direct upgrade: 2019 → 2022"
            UpgradeSteps = @("2022")
            RequiredISOs = @("2022")
            CurrentStep = "2019"
            NextStep = "2022"
        }
    }
    else {
        Write-Log "VM $($VM.Name) OS could not be determined or is not a supported upgrade candidate. Guest OS: $guestOS" -Level Warning
        return @{
            Eligible = $false
            Reason = "Unknown or unsupported OS"
            UpgradePath = "None"
            UpgradeSteps = @()
            RequiredISOs = @()
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
        [string]$TargetVersion
    )
    
    $isoVersion = $TargetVersion
    if (-not $isoVersion.StartsWith("20")) {
        $isoVersion = "20$isoVersion"
    }
    
    # Get the ISO path from the collection
    $isoKey = $TargetVersion
    if ($isoPathCollection.ContainsKey($isoKey)) {
        $isoPath = $isoPathCollection[$isoKey]
    }
    else {
        Write-Log "No ISO path defined for Windows Server $TargetVersion" -Level Error
        return $false
    }
    
    Write-Log "Mounting Windows Server $TargetVersion ISO to VM: $($VM.Name)" -Level Info
    
    try {
        # Verify ISO file exists
        if (-not (Test-Path $isoPath)) {
            Write-Log "ISO file not found: $isoPath" -Level Error
            return $false
        }
        
        # Get CD drive
        $cdDrive = Get-CDDrive -VM $VM
        
        # Check if a disk is already mounted, unmount if necessary
        if ($cdDrive.IsoPath -ne $null -and $cdDrive.IsoPath -ne "") {
            Write-Log "A disk is already mounted. Unmounting..." -Level Warning
            Set-CDDrive -CD $cdDrive -NoMedia -Confirm:$false
        }
        
        # Mount ISO
        Set-CDDrive -CD $cdDrive -IsoPath $isoPath -Connected $true -Confirm:$false
        
        # Verify mounting was successful
        $cdDrive = Get-CDDrive -VM $VM
        if ($cdDrive.IsoPath -eq $isoPath -and $cdDrive.ConnectionState.Connected) {
            Write-Log "ISO mounted successfully: $isoPath" -Level Info
            return $true
        }
        else {
            Write-Log "ISO mount verification failed" -Level Error
            return $false
        }
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
        [hashtable]$UpgradeInfo,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-Log "Initiating upgrade process on VM: $($VM.Name) - Current: $($UpgradeInfo.CurrentStep) to Next: $($UpgradeInfo.NextStep)" -Level Info
    
    try {
        # Get credentials for the VM if not provided
        if (-not $Credential) {
            if ($credentialStore.ContainsKey($VM.Name)) {
                $cred = $credentialStore[$VM.Name]
                Write-Log "Using stored credentials for $($VM.Name)" -Level Info
            }
            else {
                $cred = Get-Credential -Message "Enter administrator credentials for $($VM.Name)"
                $credentialStore[$VM.Name] = $cred
                Write-Log "Stored credentials for future use" -Level Info
            }
        }
        else {
            $cred = $Credential
        }
        
        # Establish PowerShell remote session
        $session = New-PSSession -ComputerName $VM.Guest.IPAddress -Credential $cred -ErrorAction Stop
        
        # Prepare the VM for upgrade (common across all versions)
        Invoke-Command -Session $session -ScriptBlock {
            # Create a log directory on the target server
            $logDir = "C:\WindowsUpgrade\Logs"
            if (-not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            
            # Start logging
            Start-Transcript -Path "$logDir\Upgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            
            # System preparation
            Write-Output "Starting system preparation..."
            
            # Disable Windows Update during the upgrade process
            Write-Output "Stopping Windows Update service..."
            Stop-Service -Name wuauserv -Force
            
            # Check disk space
            $systemDrive = Get-PSDrive -Name C
            Write-Output "System drive free space: $([math]::Round($systemDrive.Free / 1GB, 2)) GB"
            
            # System cleanup to free up space
            Write-Output "Running system cleanup..."
            
            # Clean up WinSxS folder (for 2012 and newer)
            if ([Environment]::OSVersion.Version.Major -ge 6 -and [Environment]::OSVersion.Version.Minor -ge 2) {
                Write-Output "Cleaning up WinSxS folder..."
                Start-Process -FilePath "Dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -Wait
            }
            
            # Clean up temp folders
            Write-Output "Cleaning up temp folders..."
            Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Ensure system is fully patched before upgrade
            Write-Output "Checking and installing Windows Updates..."
            try {
                if (Get-Command -Name Get-WindowsUpdate -ErrorAction SilentlyContinue) {
                    Write-Output "PSWindowsUpdate module already installed."
                } else {
                    Write-Output "Installing PSWindowsUpdate module..."
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
                    Install-Module PSWindowsUpdate -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber | Out-Null
                }
                
                Import-Module PSWindowsUpdate
                Get-WindowsUpdate -MicrosoftUpdate -Install -AcceptAll -IgnoreReboot -Verbose | Out-File "$logDir\WindowsUpdate.log"
            }
            catch {
                Write-Output "Warning: Unable to install updates automatically: $_"
            }
            
            Write-Output "System preparation completed."
            Stop-Transcript
        }
        
        # Now execute specific upgrade steps based on the current OS and target version
        switch ($UpgradeInfo.CurrentStep) {
            # Windows Server 2003
            "2003" {
                Write-Log "Executing Windows Server 2003 to $($UpgradeInfo.NextStep) upgrade" -Level Info
                Invoke-Command -Session $session -ScriptBlock {
                    param($nextVersion)
                    
                    Start-Transcript -Path "C:\WindowsUpgrade\Logs\Upgrade_2003_to_${nextVersion}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    
                    Write-Output "Upgrading from Windows Server 2003 to Windows Server $nextVersion"
                    
                    # Detect CD drive with the installation media
                    $cdDrive = Get-WmiObject -Class Win32_CDROMDrive | Select-Object -First 1
                    $driveLetter = $cdDrive.Drive
                    
                    # Special handling for 2003 to 2008 R2 upgrade
                    Write-Output "Starting Windows Server setup from $driveLetter"
                    if (Test-Path "$driveLetter\setup.exe") {
                        Write-Output "Found setup.exe, starting upgrade process..."
                        Start-Process -FilePath "$driveLetter\setup.exe" -ArgumentList "/unattend: /upgrade" -Wait
                        Write-Output "Setup initiated. Server will reboot automatically when ready."
                    }
                    else {
                        Write-Error "Setup.exe not found on mounted ISO at $driveLetter"
                    }
                    
                    Stop-Transcript
                } -ArgumentList $UpgradeInfo.NextStep
            }
            
            # Windows Server 2008/2008 R2
            "2008" {
                Write-Log "Executing Windows Server 2008/R2 to $($UpgradeInfo.NextStep) upgrade" -Level Info
                Invoke-Command -Session $session -ScriptBlock {
                    param($nextVersion)
                    
                    Start-Transcript -Path "C:\WindowsUpgrade\Logs\Upgrade_2008_to_${nextVersion}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    
                    Write-Output "Upgrading from Windows Server 2008/R2 to Windows Server $nextVersion"
                    
                    # Find CD drive containing the installation media
                    $cdDrive = Get-WmiObject -Class Win32_CDROMDrive | Select-Object -First 1
                    $driveLetter = $cdDrive.Drive
                    
                    if (Test-Path "$driveLetter\setup.exe") {
                        Write-Output "Found setup.exe on $driveLetter"
                        
                        # Create a temporary answer file for unattended upgrade
                        $answerFileContent = @"
[SetupData]
[UserData]
AcceptEula=Yes
[Display]
[Features]
[WindowsFeatures]
[Upgrades]
[Commands]
"@
                        $answerFile = "C:\Windows\Temp\UpgradeAnswer.ini"
                        $answerFileContent | Out-File -FilePath $answerFile -Encoding ASCII -Force
                        
                        Write-Output "Starting setup with answer file..."
                        Start-Process -FilePath "$driveLetter\setup.exe" -ArgumentList "/unattend:$answerFile /upgrade" -Wait
                        Write-Output "Setup initiated. Server will reboot automatically when ready."
                    }
                    else {
                        Write-Error "Setup.exe not found on mounted ISO at $driveLetter"
                    }
                    
                    Stop-Transcript
                } -ArgumentList $UpgradeInfo.NextStep
            }
            
            # Windows Server 2012/2012 R2
            "2012" {
                Write-Log "Executing Windows Server 2012/R2 to $($UpgradeInfo.NextStep) upgrade" -Level Info
                Invoke-Command -Session $session -ScriptBlock {
                    param($nextVersion)
                    
                    Start-Transcript -Path "C:\WindowsUpgrade\Logs\Upgrade_2012_to_${nextVersion}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    
                    Write-Output "Upgrading from Windows Server 2012/R2 to Windows Server $nextVersion"
                    
                    # 2012/R2 upgrade process is similar to 2016
                    $setupPath = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }).DriveLetter + ":\setup.exe"
                    if (Test-Path $setupPath) {
                        Write-Output "Starting Windows Server $nextVersion setup..."
                        
                        if ($nextVersion -eq "2019") {
                            # Create unattended XML file for 2019 upgrade
                            $unattendFile = "C:\Windows\Temp\unattend.xml"
                            @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserData>
                <AcceptEula>true</AcceptEula>
            </UserData>
            <ComplianceCheck>
                <DisplayReport>never</DisplayReport>
            </ComplianceCheck>
            <Upgrade>
                <IgnoreEula>true</IgnoreEula>
            </Upgrade>
        </component>
    </settings>
</unattend>
"@ | Out-File -FilePath $unattendFile -Encoding utf8
                            
                            Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade /quiet /noreboot /unattendfile:$unattendFile /compat ignorewarning" -Wait
                        }
                        else {
                            # Standard arguments for other upgrades
                            Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade /quiet /noreboot /compat ignorewarning" -Wait
                        }
                        
                        Write-Output "Setup initiated, server will reboot when ready"
                    }
                    else {
                        Write-Error "Setup.exe not found on mounted ISO"
                    }
                    
                    Stop-Transcript
                } -ArgumentList $UpgradeInfo.NextStep
            }
            
            # Windows Server 2016
            "2016" {
                Write-Log "Executing Windows Server 2016 to $($UpgradeInfo.NextStep) upgrade" -Level Info
                Invoke-Command -Session $session -ScriptBlock {
                    param($nextVersion)
                    
                    Start-Transcript -Path "C:\WindowsUpgrade\Logs\Upgrade_2016_to_${nextVersion}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    
                    Write-Output "Upgrading from Windows Server 2016 to Windows Server $nextVersion"
                    
                    # Find CD drive with installation media
                    $setupPath = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }).DriveLetter + ":\setup.exe"
                    if (Test-Path $setupPath) {
                        Write-Output "Starting Windows Server $nextVersion setup..."
                        
                        # Direct upgrade to 2022
                        Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade /quiet /noreboot /compat ignorewarning" -Wait
                        Write-Output "Setup initiated, server will reboot when ready"
                    }
                    else {
                        Write-Error "Setup.exe not found on mounted ISO"
                    }
                    
                    Stop-Transcript
                } -ArgumentList $UpgradeInfo.NextStep
            }
            
            # Windows Server 2019
            "2019" {
                Write-Log "Executing Windows Server 2019 to $($UpgradeInfo.NextStep) upgrade" -Level Info
                Invoke-Command -Session $session -ScriptBlock {
                    param($nextVersion)
                    
                    Start-Transcript -Path "C:\WindowsUpgrade\Logs\Upgrade_2019_to_${nextVersion}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    
                    Write-Output "Upgrading from Windows Server 2019 to Windows Server $nextVersion"
                    
                    # Find CD drive with installation media
                    $setupPath = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }).DriveLetter + ":\setup.exe"
                    if (Test-Path $setupPath) {
                        Write-Output "Starting Windows Server $nextVersion setup..."
                        
                        # Direct upgrade to 2022
                        Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade /quiet /noreboot /compat ignorewarning" -Wait
                        Write-Output "Setup initiated, server will reboot when ready"
                    }
                    else {
                        Write-Error "Setup.exe not found on mounted ISO"
                    }
                    
                    Stop-Transcript
                } -ArgumentList $UpgradeInfo.NextStep
            }
            
            default {
                Write-Log "Unsupported current OS version: $($UpgradeInfo.CurrentStep)" -Level Error
                Remove-PSSession -Session $session
                return $false
            }
        }
        
        # Close session
        Remove-PSSession -Session $session
        Write-Log "Upgrade process initiated on VM: $($VM.Name) - From $($UpgradeInfo.CurrentStep) to $($UpgradeInfo.NextStep)" -Level Info
        return $true
    }
    catch {
        Write-Log "Failed to initiate upgrade on VM $($VM.Name): $_" -Level Error
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
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

# Get Windows Server VMs that need upgrade
Write-Log "Searching for Windows Server VMs eligible for upgrade" -Level Info
$windowsVMs = Get-VM | Where-Object {
    $_.Guest.OSFullName -match "Windows Server (2003|2008|2012|2016|2019)" -and
    $_.Guest.OSFullName -notmatch "Windows Server 2022"
}

Write-Log "Found $($windowsVMs.Count) Windows Server VMs for potential upgrade" -Level Info

# Initialize results array
$upgradeResults = @()

# Add new functions for multi-step upgrade process

function Start-UpgradeSequence {
    param (
        [Parameter(Mandatory=$true)]
        [array]$VirtualMachines,
        
        [Parameter(Mandatory=$false)]
        [switch]$BatchMode,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $results = @()
    $runningUpgrades = @{}
    $completedUpgrades = @()
    
    # Process VMs in batch or sequential mode
    foreach ($vm in $VirtualMachines) {
        Write-Log "Starting upgrade sequence for VM: $($vm.Name)" -Level Info
        
        # Check eligibility and get upgrade path
        $upgradeInfo = Test-VMUpgradeEligibility -VM $vm
        
        $result = [PSCustomObject]@{
            VMName = $vm.Name
            GuestOS = $vm.Guest.OSFullName
            Eligible = $upgradeInfo.Eligible
            Reason = $upgradeInfo.Reason
            UpgradePath = $upgradeInfo.UpgradePath
            CurrentStep = $upgradeInfo.CurrentStep
            NextStep = $upgradeInfo.NextStep
            RequiredISOs = $upgradeInfo.RequiredISOs -join ", "
            BackupCreated = $false
            UpgradeInitiated = $false
            CompletedSteps = @()
            UpgradeStatus = "Not Started"
            StartTime = $null
            CompletionTime = $null
            Timestamp = Get-Date
        }
        
        # If eligible, continue with preparation
        if ($upgradeInfo.Eligible) {
            # Check if we've reached the maximum concurrent upgrades
            if ($BatchMode -and ($runningUpgrades.Count -ge $maxConcurrentUpgrades)) {
                Write-Log "Maximum concurrent upgrades reached. Waiting for an upgrade to complete..." -Level Warning
                $waitResult = Wait-ForUpgradeCompletion -RunningUpgrades $runningUpgrades -TimeoutMinutes 30
                if (-not $waitResult) {
                    Write-Log "Timeout waiting for upgrades to complete" -Level Error
                }
            }
            
            # Create backup
            $result.BackupCreated = Backup-VMBeforeUpgrade -VM $vm
            
            if ($result.BackupCreated) {
                # Start the upgrade process
                $result.StartTime = Get-Date
                $result.UpgradeStatus = "In Progress"
                
                # Mount ISO for next step
                $isoMounted = Mount-UpgradeISO -VM $vm -TargetVersion $upgradeInfo.NextStep
                
                if ($isoMounted) {
                    # Initiate upgrade for this step
                    $upgradeStarted = Invoke-RemoteUpgrade -VM $vm -UpgradeInfo $upgradeInfo -Credential $Credential
                    
                    if ($upgradeStarted) {
                        $result.UpgradeInitiated = $true
                        
                        if ($BatchMode) {
                            # Add to running upgrades
                            $runningUpgrades[$vm.Name] = @{
                                VM = $vm
                                StartTime = Get-Date
                                CurrentStep = $upgradeInfo.CurrentStep
                                NextStep = $upgradeInfo.NextStep
                                UpgradeInfo = $upgradeInfo
                            }
                            
                            Write-Log "Added VM $($vm.Name) to running upgrades. Currently tracking $($runningUpgrades.Count) concurrent upgrades." -Level Info
                        }
                        else {
                            # For sequential mode, wait for this upgrade to complete
                            $result.UpgradeStatus = "Waiting For Completion"
                            $upgradeCompleted = Wait-ForVMUpgrade -VM $vm -TimeoutMinutes 120
                            
                            if ($upgradeCompleted) {
                                $result.CompletedSteps += $upgradeInfo.NextStep
                                $result.UpgradeStatus = "Step Completed"
                                Write-Log "Upgrade step completed for VM $($vm.Name) from $($upgradeInfo.CurrentStep) to $($upgradeInfo.NextStep)" -Level Info
                            }
                            else {
                                $result.UpgradeStatus = "Step Timeout"
                                Write-Log "Upgrade step timed out for VM $($vm.Name)" -Level Warning
                            }
                        }
                    }
                    else {
                        $result.UpgradeStatus = "Failed to Initiate"
                        Write-Log "Failed to initiate upgrade for VM $($vm.Name)" -Level Error
                    }
                }
                else {
                    $result.UpgradeStatus = "ISO Mount Failed"
                    Write-Log "Failed to mount ISO for VM $($vm.Name)" -Level Error
                }
            }
            else {
                $result.UpgradeStatus = "Backup Failed"
                Write-Log "Failed to create backup for VM $($vm.Name)" -Level Error
            }
        }
        else {
            $result.UpgradeStatus = "Not Eligible"
        }
        
        # Add result to array
        $results += $result
    }
    
    # If in batch mode, wait for all upgrades to complete
    if ($BatchMode -and $runningUpgrades.Count -gt 0) {
        Write-Log "Waiting for remaining $($runningUpgrades.Count) upgrades to complete..." -Level Info
        Wait-ForUpgradeCompletion -RunningUpgrades $runningUpgrades -TimeoutMinutes 180
    }
    
    return $results
}

function Wait-ForVMUpgrade {
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutMinutes = 120,
        
        [Parameter(Mandatory=$false)]
        [int]$CheckIntervalSeconds = 60
    )
    
    $startTime = Get-Date
    $timeoutTime = $startTime.AddMinutes($TimeoutMinutes)
    
    Write-Log "Waiting for upgrade to complete on VM $($VM.Name)" -Level Info
    Write-Log "Timeout set to $TimeoutMinutes minutes" -Level Info
    
    do {
        # First check if VM is still running or in reboot cycle
        $currentVM = Get-VM -Name $VM.Name -ErrorAction SilentlyContinue
        
        if (-not $currentVM) {
            Write-Log "VM $($VM.Name) not found. Possible rename during upgrade?" -Level Warning
            return $false
        }
        
        $powerState = $currentVM.PowerState
        
        if ($powerState -eq "PoweredOff") {
            Write-Log "VM $($VM.Name) is powered off. Powering on..." -Level Warning
            Start-VM -VM $currentVM -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 60  # Wait for VM to boot
        }
        
        # Check if Tools are running (indicates OS is operational)
        $toolsStatus = $currentVM.Guest.ExtensionData.ToolsStatus
        
        if ($toolsStatus -eq "toolsOk") {
            # VM is operational, check if upgrade is complete
            try {
                # Try to establish connection to check status
                $cred = $credentialStore[$VM.Name]
                $ipAddress = $currentVM.Guest.IPAddress | Select-Object -First 1
                
                if ($ipAddress) {
                    $testConnection = Test-NetConnection -ComputerName $ipAddress -Port 5985 -WarningAction SilentlyContinue
                    
                    if ($testConnection.TcpTestSucceeded) {
                        # Try to establish PS session to check OS
                        $session = New-PSSession -ComputerName $ipAddress -Credential $cred -ErrorAction Stop
                        
                        $osInfo = Invoke-Command -Session $session -ScriptBlock {
                            [PSCustomObject]@{
                                OSName = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                                OSVersion = [System.Environment]::OSVersion.Version.ToString()
                                LastBootTime = (Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime
                            }
                        }
                        
                        Write-Log "Current OS on $($VM.Name): $($osInfo.OSName) - Version: $($osInfo.OSVersion)" -Level Info
                        Remove-PSSession -Session $session
                        
                        # Check if the server has been rebooted recently (indicates upgrade completed)
                        $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($osInfo.LastBootTime)
                        if ($lastBootTime -gt $startTime) {
                            Write-Log "Server $($VM.Name) has rebooted since upgrade started. Upgrade likely complete." -Level Info
                            return $true
                        }
                    }
                }
            }
            catch {
                Write-Log "Cannot verify upgrade status for $($VM.Name): $_" -Level Warning
            }
        }
        
        # Sleep before next check
        Write-Log "Upgrade still in progress. Waiting $CheckIntervalSeconds seconds..." -Level Info
        Start-Sleep -Seconds $CheckIntervalSeconds
        
    } until ((Get-Date) -gt $timeoutTime)
    
    Write-Log "Timeout reached waiting for upgrade to complete on VM $($VM.Name)" -Level Warning
    return $false
}

function Wait-ForUpgradeCompletion {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$RunningUpgrades,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutMinutes = 180
    )
    
    $startTime = Get-Date
    $timeoutTime = $startTime.AddMinutes($TimeoutMinutes)
    $completed = @()
    
    Write-Log "Waiting for completion of $($RunningUpgrades.Count) upgrades" -Level Info
    
    do {
        foreach ($vmName in @($RunningUpgrades.Keys)) {
            $vmInfo = $RunningUpgrades[$vmName]
            $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
            
            if (-not $vm) {
                Write-Log "VM $vmName not found. Marking as unknown status." -Level Warning
                $completed += $vmName
                continue
            }
            
            # Check if upgrade completed
            $upgradeComplete = Wait-ForVMUpgrade -VM $vm -TimeoutMinutes 5 -CheckIntervalSeconds 30
            
            if ($upgradeComplete) {
                Write-Log "Upgrade step completed for VM $vmName" -Level Info
                $completed += $vmName
            }
            else {
                # Check if timeout exceeded for this VM
                $vmElapsedTime = (Get-Date) - $vmInfo.StartTime
                if ($vmElapsedTime.TotalMinutes -gt $TimeoutMinutes) {
                    Write-Log "Timeout exceeded for VM $vmName. Marking as timeout." -Level Warning
                    $completed += $vmName
                }
            }
        }
        
        # Remove completed VMs from tracking
        foreach ($vmName in $completed) {
            $RunningUpgrades.Remove($vmName)
        }
        $completed = @()
        
        if ($RunningUpgrades.Count -gt 0) {
            Write-Log "Still waiting for $($RunningUpgrades.Count) upgrades to complete..." -Level Info
            Start-Sleep -Seconds ($statusCheckInterval * 60)
        }
        
    } until ($RunningUpgrades.Count -eq 0 -or (Get-Date) -gt $timeoutTime)
    
    if ($RunningUpgrades.Count -gt 0) {
        Write-Log "Timeout reached waiting for upgrade completion. $($RunningUpgrades.Count) upgrades still in progress." -Level Warning
        return $false
    }
    
    return $true
}

function Monitor-UpgradeProgress {
    param (
        [Parameter(Mandatory=$true)]
        [array]$UpgradeResults
    )
    
    $progressTable = @()
    
    foreach ($result in $UpgradeResults) {
        $progressItem = [PSCustomObject]@{
            VMName = $result.VMName
            CurrentOS = $result.GuestOS
            UpgradePath = $result.UpgradePath
            Status = $result.UpgradeStatus
            StartTime = $result.StartTime
            ElapsedTime = if ($result.StartTime) { (Get-Date) - $result.StartTime } else { $null }
            ProgressPercentage = 0
        }
        
        # Calculate progress percentage
        if ($result.UpgradePath -ne "None" -and $result.Eligible) {
            $totalSteps = ($result.UpgradePath -split " → ").Count - 1
            $completedSteps = if ($result.CompletedSteps) { $result.CompletedSteps.Count } else { 0 }
            
            if ($totalSteps -gt 0) {
                $progressItem.ProgressPercentage = [math]::Round(($completedSteps / $totalSteps) * 100)
            }
        }
        
        $progressTable += $progressItem
    }
    
    return $progressTable
}

# Begin the VM upgrade process
Write-Log "Starting VM upgrade process..." -Level Info

# Display warning for concurrent upgrades
Write-Host "IMPORTANT: This script will process VM upgrades with a maximum of $maxConcurrentUpgrades concurrent upgrades." -ForegroundColor Yellow
Write-Host "Each upgrade may require multiple steps depending on the source OS version." -ForegroundColor Yellow
Write-Host "The script will create a VM snapshot before each upgrade step." -ForegroundColor Yellow
Write-Host ""

# Prompt for batch mode
$batchMode = Read-Host "Run upgrades in batch mode? (Y/N) Default: N"
$useBatchMode = ($batchMode -eq "Y" -or $batchMode -eq "y")

# Ask for common credentials to speed up process
$useCommonCreds = Read-Host "Use common administrator credentials for all VMs? (Y/N) Default: N"
$commonCreds = $null
if ($useCommonCreds -eq "Y" -or $useCommonCreds -eq "y") {
    $commonCreds = Get-Credential -Message "Enter administrator credentials to use for all VMs"
}

# Process each VM for upgrade
$upgradeResults = @()

# Get list of VMs to upgrade
$filteredVMs = @()
foreach ($vm in $windowsVMs) {
    $eligibility = Test-VMUpgradeEligibility -VM $vm
    
    if ($eligibility.Eligible) {
        $filteredVMs += $vm
        
        # Display upgrade path
        Write-Host "VM: $($vm.Name)" -ForegroundColor Cyan
        Write-Host "  Current OS: $($vm.Guest.OSFullName)" -ForegroundColor Gray
        Write-Host "  Upgrade Path: $($eligibility.UpgradePath)" -ForegroundColor Gray
        Write-Host "  Required ISOs: $($eligibility.RequiredISOs -join ', ')" -ForegroundColor Gray
        Write-Host ""
    }
    else {
        Write-Host "VM: $($vm.Name) - Not eligible: $($eligibility.Reason)" -ForegroundColor Yellow
    }
}

# Confirm before proceeding
$confirmation = Read-Host "Ready to proceed with upgrade of $($filteredVMs.Count) VMs? (Y/N)"
if ($confirmation -ne "Y" -and $confirmation -ne "y") {
    Write-Log "Upgrade cancelled by user" -Level Warning
    # Display cancellation report
    Generate-UpgradeReport -UpgradeResults @()
    exit
}

# Start the upgrade sequence
$upgradeResults = Start-UpgradeSequence -VirtualMachines $filteredVMs -BatchMode:$useBatchMode -Credential $commonCreds

# Generate report
$summary = Generate-UpgradeReport -UpgradeResults $upgradeResults

# Display summary
Write-Host "`n$summary" -ForegroundColor Green

# Disconnect from vCenter
Disconnect-VIServer -Server $vCenterServer -Confirm:$false
Write-Log "Disconnected from vCenter" -Level Info
Write-Log "Script completed" -Level Info
#endregion