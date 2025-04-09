#requires -Modules VMware.PowerCLI
# Windows Server Upgrade Script
# This script helps upgrade Windows Server 2003, 2008, 2008 R2, 2012, 2012R2, 2016, and 2019 VMs to Windows Server 2022
# Prerequisites: PowerCLI module, administrative access to vCenter, Windows Server ISOs for intermediate upgrades

# Check if PowerShell is running with elevated privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Display warning if not running as administrator
if (-not $isAdmin) {
    Write-Warning "This script is not running with elevated privileges. Calling the servers to preform Windows Update will fail."
}
# Import PowerCLI module
Import-Module VMware.PowerCLI

# Set PowerCLI configuration
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Confirm:$false | Out-Null


#region Configuration Parameters
# Update these parameters as needed




# ISO path patterns for different Windows Server versions
$isoNameCollection = @{

    "2008" = "2008"
    "2012" = "2012"
    "2016" = "2016"
    "2019" = "2019"
    "2022" = "2022"
}

# Backup and log locations
$backupLocation = "\\emcisl01\ITG\Servers\Win VM vsphere config backups"
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

$vCenterServer = "lc1pvm-vcenter.lee-county-fl.gov"
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


function Get-VMByDNSHostname {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DNSHostname
    )
    
    Write-Log "Searching for VM with DNS hostname: $DNSHostname" -Level Info
    
    try {
        # Create variants of the hostname to search for (with and without domain)
        $shortName = $DNSHostname -replace '\..*$', ''
        
        # Get all VMs once for better performance - filter out replica and CDP VMs
        $allVMs = Get-VM | Where-Object { 
            $_.Name -notlike "*replica*" -and 
            $_.Name -notlike "*CDP*" 
        }
        
        # First try: exact match on Guest.HostName
        $vms = $allVMs | Where-Object { 
            ($_.Guest.HostName -eq $DNSHostname) -or 
            ($_.Guest.HostName -eq $shortName) 
        }
        
        if ($vms -and ($vms.Count -eq 1)) {
            Write-Log "Found VM '$($vms.Name)' with exact hostname match: $DNSHostname" -Level Info
            return $vms
        } elseif ($vms -and ($vms.Count -gt 1)) {
            Write-Log "Found multiple VMs with exact hostname match: $DNSHostname. Showing selection menu." -Level Warning
            return Show-VMSelectionMenu -VMs $vms -Hostname $DNSHostname
        }
        
        # Second try: partial match on Guest.HostName
        $vms = $allVMs | Where-Object { 
            ($_.Guest.HostName -like "*$DNSHostname*") -or 
            ($_.Guest.HostName -like "*$shortName*") 
        }
        
        if ($vms -and ($vms.Count -eq 1)) {
            Write-Log "Found VM '$($vms.Name)' with partial hostname match: $DNSHostname" -Level Info
            return $vms
        } elseif ($vms -and ($vms.Count -gt 1)) {
            Write-Log "Found multiple VMs with partial hostname match: $DNSHostname. Showing selection menu." -Level Warning
            return Show-VMSelectionMenu -VMs $vms -Hostname $DNSHostname
        }
        
        # Third try: check if the display name contains the hostname
        $vms = $allVMs | Where-Object { 
            ($_.Name -eq $DNSHostname) -or 
            ($_.Name -eq $shortName) -or
            ($_.Name -like "*$DNSHostname*") -or 
            ($_.Name -like "*$shortName*") 
        }
        
        if ($vms -and ($vms.Count -eq 1)) {
            Write-Log "Found VM '$($vms.Name)' with name matching pattern: $DNSHostname" -Level Info
            return $vms
        } elseif ($vms -and ($vms.Count -gt 1)) {
            Write-Log "Found multiple VMs with partial name match: $DNSHostname. Showing selection menu." -Level Warning
            return Show-VMSelectionMenu -VMs $vms -Hostname $DNSHostname
        }
        
        Write-Log "No VM found with DNS hostname: $DNSHostname" -Level Warning
        return $null
    }
    catch {
        Write-Log "Error searching for VM with DNS hostname $DNSHostname`: $_" -Level Error
        return $null
    }
}

function Show-VMSelectionMenu {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$VMs,
        
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )
    
    Write-Host "`nMultiple VMs found matching hostname: $Hostname" -ForegroundColor Yellow
    Write-Host "Please select the correct VM:" -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $VMs.Count; $i++) {
        Write-Host "[$($i+1)] $($VMs[$i].Name) - Guest OS: $($VMs[$i].Guest.OSFullName) - Hostname: $($VMs[$i].Guest.HostName)" -ForegroundColor Cyan
    }
    
    Write-Host "[0] None of these - skip this hostname" -ForegroundColor Red
    
    do {
        $selection = Read-Host "Enter selection (0-$($VMs.Count))"
        $validSelection = $selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -le $VMs.Count
        
        if (-not $validSelection) {
            Write-Host "Invalid selection. Please enter a number between 0 and $($VMs.Count)" -ForegroundColor Red
        }
    } while (-not $validSelection)
    
    $selection = [int]$selection
    
    if ($selection -eq 0) {
        Write-Log "User chose to skip VM with hostname: $Hostname" -Level Warning
        return $null
    } else {
        $selectedVM = $VMs[$selection-1]
        Write-Log "User selected VM: $($selectedVM.Name) for hostname: $Hostname" -Level Info
        return $selectedVM
    }
}

function Get-TargetVMsList {
    [CmdletBinding()]
    param()
    
    $vms = @()
    $method = Read-Host "How would you like to specify VMs to upgrade?`n[1] Enter DNS hostnames manually`n[2] Import from a text file`nEnter choice (1 or 2)"
    
    if ($method -eq "1") {
        # Manual entry
        Write-Host "Enter DNS hostnames of VMs to upgrade (one per line, enter blank line when done):" -ForegroundColor Cyan
        do {
            $hostname = Read-Host "DNS Hostname"
            if ($hostname) {
                $vm = Get-VMByDNSHostname -DNSHostname $hostname
                if ($vm) {
                    # Additional check to filter out replica and CDP VMs (as a safety)
                    if ($vm.Name -notlike "*replica*" -and $vm.Name -notlike "*CDP*") {
                        $vms += $vm
                        Write-Host "Added VM: $($vm.Name) with DNS hostname: $hostname" -ForegroundColor Green
                    } else {
                        Write-Host "Skipped VM: $($vm.Name) as it appears to be a replica or CDP VM" -ForegroundColor Yellow
                        Write-Log "Skipped replica or CDP VM: $($vm.Name) with hostname: $hostname" -Level Warning
                    }
                }
            }
        } while ($hostname)
    }
    elseif ($method -eq "2") {
        # Import from file
        $filePath = Read-Host "Enter the full path to the text file containing DNS hostnames (one per line)"
        if (Test-Path -Path $filePath) {
            $hostnames = Get-Content -Path $filePath | Where-Object { $_ -match '\S' }  # Skip empty lines
            Write-Host "Found $($hostnames.Count) hostnames in file" -ForegroundColor Cyan
            
            foreach ($hostname in $hostnames) {
                Write-Host "Processing hostname: $hostname" -ForegroundColor Gray
                $vm = Get-VMByDNSHostname -DNSHostname $hostname
                if ($vm) {
                    # Additional check to filter out replica and CDP VMs
                    if ($vm.Name -notlike "*replica*" -and $vm.Name -notlike "*CDP*") {
                        $vms += $vm
                        Write-Host "Added VM: $($vm.Name) with DNS hostname: $hostname" -ForegroundColor Green
                    } else {
                        Write-Host "Skipped VM: $($vm.Name) as it appears to be a replica or CDP VM" -ForegroundColor Yellow
                        Write-Log "Skipped replica or CDP VM: $($vm.Name) with hostname: $hostname" -Level Warning
                    }
                }
            }
        }
        else {
            Write-Host "File not found: $filePath" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Invalid choice. Defaulting to manual entry." -ForegroundColor Yellow
        return Get-TargetVMsList
    }
    
    # Check if any VMs were found
    if ($vms.Count -eq 0) {
        Write-Host "No VMs found with the provided DNS hostnames." -ForegroundColor Red
        $retry = Read-Host "Would you like to try again? (Y/N)"
        if ($retry -eq "Y" -or $retry -eq "y") {
            return Get-TargetVMsList
        }
        else {
            return $null
        }
    }
    
    # Display summary of VMs found
    Write-Host "`nFound $($vms.Count) VMs for upgrade:" -ForegroundColor Green
    $vms | ForEach-Object {
        Write-Host "  - $($_.Name) - Guest OS: $($_.Guest.OSFullName) - Hostname: $($_.Guest.HostName)" -ForegroundColor Cyan
    }
    
    # Confirm with user
    $confirm = Read-Host "Do you want to proceed with these VMs? (Y/N)"
    if ($confirm -eq "Y" -or $confirm -eq "y") {
        return $vms
    }
    else {
        Write-Host "VM selection cancelled." -ForegroundColor Yellow
        $retry = Read-Host "Would you like to try again? (Y/N)"
        if ($retry -eq "Y" -or $retry -eq "y") {
            return Get-TargetVMsList
        }
        else {
            return $null
        }
    }
}

$windowsVMs = Get-TargetVMsList

if (-not $windowsVMs -or $windowsVMs.Count -eq 0) {
    Write-Log "No VMs selected for upgrade. Exiting script." -Level Warning
    Disconnect-VIServer -Server $vCenterServer -Confirm:$false -ErrorAction SilentlyContinue
    exit
}

Write-Log "Found $($windowsVMs.Count) Windows Server VMs for potential upgrade" -Level Info
Write-Host "Note: VMs with 'replica' or 'CDP' in their names were automatically excluded from selection" -ForegroundColor Yellow

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
            UpgradePath = "Multi-step upgrade: 2003 to 2008 R2 to 2012 R2 to 2019 to 2022"
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
            UpgradePath = "Multi-step upgrade: 2008 to 2012 R2 to 2019 to 2022"
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
            UpgradePath = "Multi-step upgrade: 2008 R2 to 2012 R2 to 2019 to 2022"
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
            Reason = "Two-step upgrade required"
            UpgradePath = "Two-step upgrade: 2012 R2 to 2019 to 2022"
            UpgradeSteps = @("2019", "2022")
            RequiredISOs = @("2019", "2022")
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
            UpgradePath = "Two-step upgrade: 2012 R2 to 2019 to 2022"
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
            UpgradePath = "Direct upgrade: 2016 to 2022"
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
            UpgradePath = "Direct upgrade: 2019 to 2022"
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

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetVersion,
        
        [Parameter(Mandatory=$false)]
        [string]$PrimaryDatastore = "ISO's And Admin Tools NAP",
        
        [Parameter(Mandatory=$false)]
        [string]$FallbackDatastore = "ISO's And Admin Tools EOC",
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [switch]$Detailed
    )
    
    # Console output with step header
    Write-Host "`n===========================" -ForegroundColor Cyan
    Write-Host " ISO MOUNT OPERATION START " -ForegroundColor Cyan
    Write-Host "===========================`n" -ForegroundColor Cyan
    Write-Host "STEP 1: Initializing parameters" -ForegroundColor Yellow
    Write-Host "  VM: $($VM.Name)" -ForegroundColor Gray
    Write-Host "  Target Version: $TargetVersion" -ForegroundColor Gray
    Write-Host "  Primary Datastore: $PrimaryDatastore" -ForegroundColor Gray
    Write-Host "  Fallback Datastore: $FallbackDatastore" -ForegroundColor Gray
    Write-Host "  Force Unmount: $Force" -ForegroundColor Gray
    
    # Initialize result object for detailed output
    $result = @{
        Success = $false
        VM = $VM.Name
        TargetVersion = $TargetVersion
        ISOName = $null
        ErrorMessage = $null
        Datastore = $null
        MountedPath = $null
        TimeStamp = Get-Date
    }
    
    # Normalize version string (add "20" prefix if needed)
    $versionKey = $TargetVersion
    if ($versionKey.Length -eq 2 -or $versionKey.Length -eq 4) {
        if (-not $versionKey.StartsWith("20")) {
            $versionDisplay = "20$versionKey"
        } else {
            $versionDisplay = $versionKey
        }
    } else {
        $versionDisplay = $versionKey
    }
    
    Write-Log "Attempting to mount Windows Server $versionDisplay ISO for VM: $($VM.Name)" -Level Info
    Write-Host "`nSTEP 2: Checking VM status" -ForegroundColor Yellow
    
    try {
        # Verify VM is valid
        if ($VM.PowerState -ne "PoweredOn") {
            $message = "VM is not powered on. Current state: $($VM.PowerState)"
            Write-Log $message -Level Warning
            Write-Host "  ERROR: $message" -ForegroundColor Red
            $result.ErrorMessage = $message
            if ($Detailed) { return $result } else { return $false }
        }
        Write-Host "  VM power state: $($VM.PowerState)" -ForegroundColor Green
        
        # Get CD drive

        Write-Host "`nSTEP 3: Checking CD/DVD drive" -ForegroundColor Yellow
        Write-Log "Getting CD/DVD drive for VM: $($VM.Name)" -Level Info
        $cdDrive = Get-CDDrive -VM $VM
        
        if (-not $cdDrive) {
            $message = "No CD/DVD drive found on VM $($VM.Name)"
            Write-Log $message -Level Error
            Write-Host "  ERROR: $message" -ForegroundColor Red
            $result.ErrorMessage = $message
            if ($Detailed) { return $result } else { return $false }
        }
        Write-Host "  Found CD drive: $($cdDrive.Name)" -ForegroundColor Green
        
        # Store current ISO path if any
        $currentIsoPath = $cdDrive.IsoPath
        $isIsoMounted = ($currentIsoPath -ne $null -and $currentIsoPath -ne "")
        
        if ($isIsoMounted) {
            Write-Host "  Current ISO path: $currentIsoPath" -ForegroundColor Gray
        } else {
            Write-Host "  No ISO currently mounted" -ForegroundColor Gray
        }
        
        # Get the ISO name pattern to search for
        Write-Host "`nSTEP 4: Determining ISO pattern to search for" -ForegroundColor Yellow
        $isoPattern = $null
        
        # Check if we have a defined name in the collection
        if ($isoNameCollection.ContainsKey($versionKey)) {
            $isoPattern = $isoNameCollection[$versionKey]
            Write-Log "Using ISO name pattern from collection: $isoPattern" -Level Info
            Write-Host "  Using predefined pattern: $isoPattern" -ForegroundColor Green
        } else {
            # Fallback to generic pattern
            $isoPattern = "Windows Server $versionDisplay"
            Write-Log "Using fallback ISO name pattern: $isoPattern" -Level Warning
            Write-Host "  Using fallback pattern: $isoPattern" -ForegroundColor Yellow
        }
        
        # Function to try mounting ISO from a specific datastore
        function TryMountIsoFromDatastore {
            param (
                [string]$Datastore,
                [string]$DisplayName
            )
            
            Write-Host "`nSTEP 5$(if ($DisplayName -eq "fallback") { "b" } else { '' }): Locating ISO in $DisplayName datastore" -ForegroundColor Yellow
            Write-Host "  Datastore: $Datastore" -ForegroundColor Gray
            
            # Find the ISO (without mounting)
            $isoInfo = Find-ISOInDatastore -Datastore $Datastore -ISOPattern $isoPattern
            
            if (-not $isoInfo.Success) {
                Write-Host "  Could not find ISO in $DisplayName datastore: $($isoInfo.ErrorMessage)" -ForegroundColor Yellow
                return @{
                    Success = $false
                    ErrorMessage = $isoInfo.ErrorMessage
                }
            }
            
            Write-Host "  Found ISO in $DisplayName datastore: $($isoInfo.ISOName)" -ForegroundColor Green
            $targetIsoPath = $isoInfo.ISOPath
            $targetIsoName = $isoInfo.ISOName
            
            # Check if this exact ISO is already mounted
            if ($isIsoMounted -and $currentIsoPath -eq $targetIsoPath) {
                Write-Host "  The correct ISO is already mounted. No changes needed." -ForegroundColor Green
                Write-Log "Correct ISO already mounted: $targetIsoName" -Level Info
                
                return @{
                    Success = $true
                    ISOName = $targetIsoName
                    ISOPath = $targetIsoPath
                    Datastore = $Datastore
                    AlreadyMounted = $true
                }
            }
            
            # Now proceed with mounting the ISO
            Write-Host "`nSTEP 6: Mounting ISO from $DisplayName datastore" -ForegroundColor Yellow
            Write-Host "  Mounting ISO: $targetIsoName" -ForegroundColor Gray
            Write-Host "  From datastore: $Datastore" -ForegroundColor Gray
            
            # Mount the ISO
            $mountResult = Mount-ISO -VM $VM -CDDrive $cdDrive -ISOPath $targetIsoPath -ISOName $targetIsoName
            
            if (-not $mountResult.Success) {
                Write-Host "  WARNING: Failed to mount ISO: $($mountResult.ErrorMessage)" -ForegroundColor Yellow
                Write-Log "Failed to mount ISO from $DisplayName datastore: $($mountResult.ErrorMessage)" -Level Warning
                
                return @{
                    Success = $false
                    ErrorMessage = $mountResult.ErrorMessage
                }
            }
            
            Write-Host "  Successfully mounted ISO" -ForegroundColor Green
            
            return @{
                Success = $true
                ISOName = $targetIsoName
                ISOPath = $targetIsoPath
                Datastore = $Datastore
                AlreadyMounted = $false
            }
        }
# Check if this exact ISO is already mounted
if ($isIsoMounted) {
    if ($currentIsoPath -eq $targetIsoPath) {
        Write-Host "  The correct ISO is already mounted. No changes needed." -ForegroundColor Green
        Write-Log "Correct ISO already mounted: $targetIsoName" -Level Info
        
        return @{
            Success = $true
            ISOName = $targetIsoName
            ISOPath = $targetIsoPath
            Datastore = $Datastore
            AlreadyMounted = $true
        }
    }
    else {
        # A different ISO is mounted, unmount it
        Write-Log "Different ISO is currently mounted. Attempting to unmount." -Level Info
        $unmountResult = Unmount-UpgradeISO -VM $VM
        
        if (-not $unmountResult) {
            $message = "Failed to unmount existing ISO: $currentIsoPath"
            Write-Log $message -Level Error
            Write-Host "  ERROR: $message" -ForegroundColor Red
            $result.ErrorMessage = $message
            $result.MountedPath = $currentIsoPath
            
            if ($Detailed) { return $result } else { return $false }
        }
        
        Write-Log "Successfully unmounted previous ISO" -Level Info
    }
}
        
        # Try primary datastore first
        $primaryResult = TryMountIsoFromDatastore -Datastore $PrimaryDatastore -DisplayName "primary"
        
        if ($primaryResult.Success) {
            # Success with primary datastore
            $result.Success = $true
            $result.ISOName = $primaryResult.ISOName
            $result.MountedPath = $primaryResult.ISOPath
            $result.Datastore = $primaryResult.Datastore
            
            if ($primaryResult.AlreadyMounted) {
                Write-Host "`n==========================" -ForegroundColor Cyan
                Write-Host " ISO ALREADY CORRECTLY MOUNTED " -ForegroundColor Cyan
                Write-Host "==========================`n" -ForegroundColor Cyan
            } else {
                Write-Host "`n==========================" -ForegroundColor Cyan
                Write-Host " ISO MOUNT OPERATION COMPLETE " -ForegroundColor Cyan
                Write-Host "==========================`n" -ForegroundColor Cyan
            }
            
            if ($Detailed) { return $result } else { return $true }
        }
        
        # If primary fails, try fallback datastore
        $fallbackResult = TryMountIsoFromDatastore -Datastore $FallbackDatastore -DisplayName "fallback"
        
        if ($fallbackResult.Success) {
            # Success with fallback datastore
            $result.Success = $true
            $result.ISOName = $fallbackResult.ISOName
            $result.MountedPath = $fallbackResult.ISOPath
            $result.Datastore = $fallbackResult.Datastore
            
            if ($fallbackResult.AlreadyMounted) {
                Write-Host "`n==========================" -ForegroundColor Cyan
                Write-Host " ISO ALREADY CORRECTLY MOUNTED " -ForegroundColor Cyan
                Write-Host "==========================`n" -ForegroundColor Cyan
            } else {
                Write-Host "`n==========================" -ForegroundColor Cyan
                Write-Host " ISO MOUNT OPERATION COMPLETE " -ForegroundColor Cyan
                Write-Host "==========================`n" -ForegroundColor Cyan
            }
            
            if ($Detailed) { return $result } else { return $true }
        }
        
        # If we get here, both datastores failed
        $message = "Could not mount ISO from either datastore"
        Write-Log $message -Level Error
        Write-Host "  ERROR: $message" -ForegroundColor Red
        Write-Host "  Primary error: $($primaryResult.ErrorMessage)" -ForegroundColor Red
        Write-Host "  Fallback error: $($fallbackResult.ErrorMessage)" -ForegroundColor Red
        
        $result.ErrorMessage = $message
        
        Write-Host "`n==========================" -ForegroundColor Red
        Write-Host " ISO MOUNT OPERATION FAILED " -ForegroundColor Red
        Write-Host "==========================`n" -ForegroundColor Red
        
        if ($Detailed) { return $result } else { return $false }
    }
    catch {
        $message = "Error mounting ISO: $_"
        Write-Log $message -Level Error
        Write-Host "`n  ERROR: $message" -ForegroundColor Red
        $result.ErrorMessage = $message
        
        Write-Host "`n==========================" -ForegroundColor Red
        Write-Host " ISO MOUNT OPERATION FAILED " -ForegroundColor Red
        Write-Host "==========================`n" -ForegroundColor Red
        
        if ($Detailed) { 
            return $result 
        } else { 
            return $false 
        }
    }
}
function Find-ISOInDatastore {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Datastore,
        
        [Parameter(Mandatory=$true)]
        [string]$ISOPattern
    )
    
    $result = @{
        Success = $false
        ISOName = $null
        ISOPath = $null
        ErrorMessage = $null
    }
    
    try {
        # Check if datastore exists
        $ds = Get-Datastore -Name $Datastore -ErrorAction Stop
        
        if (-not $ds) {
            throw "Datastore '$Datastore' not found"
        }
        
        # Create a temporary PSDrive
        $driveName = -join ((65..90) | Get-Random -Count 3 | ForEach-Object -Process { [char]$_ })
        New-PSDrive -Name $driveName -PSProvider VimDatastore -Root '\' -Location $ds | Out-Null
        
        try {
            # Define search patterns
            $searchPattern = "*$ISOPattern*.iso"
            
            # Search for matching ISOs
            $isoFiles = Get-ChildItem -Path "$($driveName):" -Filter $searchPattern -Recurse | 
                        Where-Object { $_.Name -like "*.iso" } |
                        Sort-Object -Property LastWriteTime -Descending
            
            if (-not $isoFiles -or $isoFiles.Count -eq 0) {
                throw "No ISO files matching pattern '$searchPattern' found in datastore '$Datastore'"
            }
            
            # Select the most recent ISO
            $selectedISO = $isoFiles | Select-Object -First 1
            
            # Get the full datastore path
            $result.ISOName = $selectedISO.Name
            $result.ISOPath = $selectedISO.DatastoreFullPath
            $result.Success = $true
            
            return $result
        }
        finally {
            # Clean up the temporary PSDrive
            if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
                Remove-PSDrive -Name $driveName -Confirm:$false | Out-Null
            }
        }
    }
    catch {
        $message = "Error finding ISO in datastore $Datastore $_"
        $result.ErrorMessage = $message
        return $result
    }
}

function Mount-ISO {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.VirtualDevice.CDDrive]$CDDrive,
        
        [Parameter(Mandatory=$true)]
        [string]$ISOPath,
        
        [Parameter(Mandatory=$true)]
        [string]$ISOName
    )
    
    $result = @{
        Success = $false
        ErrorMessage = $null
    }
    
    try {
        # Create config spec to edit the CD drive
        $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        
        $change = New-Object VMware.Vim.VirtualDeviceConfigSpec
        $change.Operation = [VMware.Vim.VirtualDeviceConfigSpecOperation]::edit
        
        # Get the CD drive device
        $dev = $CDDrive.ExtensionData
        $dev.Backing = New-Object VMware.Vim.VirtualCdromIsoBackingInfo
        $dev.Backing.FileName = $ISOPath
        
        # Connect the drive
        $dev.Connectable.Connected = $true
        $dev.Connectable.StartConnected = $true
        
        $change.Device = $dev
        $spec.DeviceChange = @($change)
        
        # Apply the changes
        Write-Log "Applying configuration to mount ISO: $ISOName" -Level Info
        $VM.ExtensionData.ReconfigVM($spec)
        
        # Get the updated CD drive to verify
        Start-Sleep -Seconds 2
        $updatedCdDrive = Get-CDDrive -Id $CDDrive.Id
        
        if ($updatedCdDrive.IsoPath -eq $ISOPath) {
            Write-Log "ISO successfully mounted: $ISOName" -Level Info
            $result.Success = $true
            return $result
        } else {
            $message = "ISO mount verification failed"
            Write-Log $message -Level Error
            $result.ErrorMessage = $message
            return $result
        }
    }
    catch {
        $message = "Error mounting ISO: $_"
        Write-Log $message -Level Error
        $result.ErrorMessage = $message
        return $result
    }
}
#endregion

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
        $session = New-PSSession -ComputerName $VM.Guest.HostName -Credential $cred -ErrorAction Stop
        
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
                #Get-WindowssUpdate -Install -AcceptAll -IgnoreReboot -ComputerName $VM.Guest.HostName -Verbose -Confirm:$false | Out-File "$logDir\WindowsUpdate.log"
            }
            catch {
                Write-Output "Warning: Unable to install updates automatically: $_"
            }
            
            Write-Output "System preparation completed."
            Stop-Transcript
        }
        
        # Now execute specific upgrade steps based on the current OS and target version
        switch ($UpgradeInfo.CurrentStep) {            
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
                        Start-Process -FilePath "$driveLetter\setup.exe" -ArgumentList "/quiet /auto upgrade /dynamicupdate disable /migratedrivers all /showoobe none /imageindex 2 /compat ignorewarning" -Wait
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
                            Start-Process -FilePath $setupPath -ArgumentList "/quiet /auto upgrade /dynamicupdate disable /migratedrivers all /showoobe none /imageindex 2 /compat ignorewarning" -Wait
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
                        Start-Process -FilePath $setupPath -ArgumentList "/quiet /auto upgrade /dynamicupdate disable /migratedrivers all /showoobe none /imageindex 2 /compat ignorewarning" -Wait
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
                        Start-Process -FilePath $setupPath -ArgumentList "/quiet /auto upgrade /dynamicupdate disable /migratedrivers all /showoobe none /imageindex 2 /compat ignorewarning" -Wait
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
    
    # Calculate counts properly
    $totalVMs = $UpgradeResults.Count
    $directUpgradeVMs = ($UpgradeResults | Where-Object { $_.UpgradePath -match "Direct upgrade:" } | Measure-Object).Count
    $intermediateUpgradeVMs = ($UpgradeResults | Where-Object { $_.UpgradePath -match "Multi-step upgrade:|Two-step upgrade:" } | Measure-Object).Count
    $notEligibleVMs = ($UpgradeResults | Where-Object { $_.UpgradePath -eq "None" } | Measure-Object).Count
    $initiatedUpgrades = ($UpgradeResults | Where-Object { $_.UpgradeInitiated -eq $true } | Measure-Object).Count
    $failedUpgrades = ($UpgradeResults | Where-Object { $_.UpgradeInitiated -eq $false -and $_.Eligible -eq $true } | Measure-Object).Count
    
    # Create summary with pre-calculated values
    $summary = @"
Windows Server Upgrade Summary
-----------------------------
Total VMs processed: $totalVMs
VMs eligible for direct upgrade: $directUpgradeVMs
VMs requiring intermediate upgrade: $intermediateUpgradeVMs
VMs not eligible for upgrade: $notEligibleVMs

Upgrade processes initiated: $initiatedUpgrades
Upgrade processes failed: $failedUpgrades

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
Write-Log "Script configuration: vCenter=$vCenterServer" -Level Info
Write-Log "Found $($windowsVMs.Count) Windows Server VMs for potential upgrade" -Level Info

# Initialize results array
$upgradeResults = @()

#Function to handle ISO unmounting
function Unmount-UpgradeISO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )
    
    try {
        Write-Log "Unmounting ISO from VM: $($VM.Name)" -Level Info
        Write-Host "  Unmounting ISO from VM..." -ForegroundColor Yellow
        
        # Use PowerCLI's Set-CDDrive with -NoMedia parameter to unmount the ISO
        $VM | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false | Out-Null
        
        # Verify the unmount
        Start-Sleep -Seconds 2
        $cdDrive = $VM | Get-CDDrive
        
        if (-not $cdDrive.IsoPath) {
            Write-Log "ISO successfully unmounted from VM $($VM.Name)" -Level Info
            Write-Host "  ISO successfully unmounted" -ForegroundColor Green
        } else {
            Write-Log "Failed to verify ISO unmount from VM $($VM.Name)" -Level Warning
        }
    }
    catch {
        Write-Log "Error unmounting ISO from VM $($VM.Name): $_" -Level Error
        Write-Host "  ERROR: Failed to unmount ISO: $_" -ForegroundColor Red
    }
}

# Updated Start-UpgradeSequence function with ISO unmounting
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
            ISOUnmounted = $false
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
                
                # Show progress after waiting
                if ($results.Count -gt 0) {
                    $progressTable = Monitor-UpgradeProgress -UpgradeResults $results
                    Write-Host "`nCurrent Upgrade Progress:" -ForegroundColor Cyan
                    $progressTable | Format-Table -Property VMName, CurrentOS, Status, ProgressPercentage, ElapsedTime
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
                                
                                # Unmount ISO after completion in sequential mode
                                Write-Log "Unmounting ISO after successful upgrade" -Level Info
                                $result.ISOUnmounted = Unmount-UpgradeISO -VM $vm
                            }
                            else {
                                $result.UpgradeStatus = "Step Timeout"
                                Write-Log "Upgrade step timed out for VM $($vm.Name)" -Level Warning
                                
                                # Still try to unmount ISO even after timeout
                                Write-Log "Attempting to unmount ISO after timeout" -Level Info
                                $result.ISOUnmounted = Unmount-UpgradeISO -VM $vm
                            }
                        }
                    }
                    else {
                        $result.UpgradeStatus = "Failed to Initiate"
                        Write-Log "Failed to initiate upgrade for VM $($vm.Name)" -Level Error
                        
                        # Unmount ISO if upgrade failed to initiate
                        Write-Log "Unmounting ISO after failed upgrade initiation" -Level Info
                        $result.ISOUnmounted = Unmount-UpgradeISO -VM $vm
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
        
        # Display progress after each VM is processed
        if ($results.Count -gt 0 -and $results.Count % 3 -eq 0) {
            $progressTable = Monitor-UpgradeProgress -UpgradeResults $results
            Write-Host "`nIntermediate Upgrade Progress:" -ForegroundColor Cyan
            $progressTable | Format-Table -Property VMName, CurrentOS, Status, ProgressPercentage, ElapsedTime
        }
    }
    
    # If in batch mode, wait for all upgrades to complete and unmount ISOs
    if ($BatchMode -and $runningUpgrades.Count -gt 0) {
        Write-Log "Waiting for remaining $($runningUpgrades.Count) upgrades to complete..." -Level Info
        $batchCompleted = Wait-ForUpgradeCompletion -RunningUpgrades $runningUpgrades -TimeoutMinutes 180
        
        # Unmount ISOs for all VMs in batch mode
        Write-Log "Unmounting ISOs from all VMs after batch completion" -Level Info
        Write-Host "`nUnmounting ISOs from completed VMs..." -ForegroundColor Yellow
        
        foreach ($result in $results) {
            if ($result.UpgradeInitiated -eq $true) {
                $vm = Get-VM -Name $result.VMName -ErrorAction SilentlyContinue
                if ($vm) {
                    $isoUnmounted = Unmount-UpgradeISO -VM $vm
                    
                    # Update result with unmount status
                    $existingResult = $results | Where-Object { $_.VMName -eq $vm.Name } | Select-Object -First 1
                    if ($existingResult) {
                        $existingResult.ISOUnmounted = $isoUnmounted
                    }
                    
                    Write-Host "  VM: $($vm.Name) - ISO Unmounted: $isoUnmounted" -ForegroundColor $(if ($isoUnmounted) { "Green" } else { "Red" })
                }
            }
        }
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
                $ipAddress = $currentVM.Guest.Hostname | Select-Object -First 1
                
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
            
            # Display current progress
            Write-Host "`nCurrent Upgrade Status:" -ForegroundColor Cyan
            $currentProgress = [System.Collections.ArrayList]@()
            
            foreach ($vmName in $RunningUpgrades.Keys) {
                $vmInfo = $RunningUpgrades[$vmName]
                $elapsedTime = (Get-Date) - $vmInfo.StartTime
                
                $progressItem = [PSCustomObject]@{
                    VMName = $vmName
                    CurrentOS = $vmInfo.VM.Guest.OSFullName
                    Upgrading = "From $($vmInfo.CurrentStep) to $($vmInfo.NextStep)"
                    ElapsedTime = "$([math]::Round($elapsedTime.TotalMinutes, 0)) minutes"
                    Status = "In Progress"
                }
                
                $currentProgress.Add($progressItem) | Out-Null
            }
            
            $currentProgress | Format-Table -AutoSize
            
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
            $totalSteps = ($result.UpgradePath -split " to ").Count - 1
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
    Generate-UpgradeReport -UpgradeResults @() -ErrorAction SilentlyContinue
    exit
}

# Start the upgrade sequence
$upgradeResults = Start-UpgradeSequence -VirtualMachines $filteredVMs -BatchMode:$useBatchMode -Credential $commonCreds

# Display upgrade progress summary
$progressTable = Monitor-UpgradeProgress -UpgradeResults $upgradeResults
Write-Host "`nUpgrade Progress Summary:" -ForegroundColor Cyan
$progressTable | Format-Table -Property VMName, CurrentOS, Status, ProgressPercentage, ElapsedTime

# Generate report
$summary = Generate-UpgradeReport -UpgradeResults $upgradeResults

# Display summary
Write-Host "`n$summary" -ForegroundColor Green

# Disconnect from vCenter
Disconnect-VIServer -Server $vCenterServer -Confirm:$false
Write-Log "Disconnected from vCenter" -Level Info
Write-Log "Script completed" -Level Info
#endregion