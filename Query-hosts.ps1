connect-viServer -Server lc1pvm-vcenter.lee-county-fl.gov -Protocol https -Force #-Credential (Get-Credential)

# Query DNS configuration for all ESXi hosts
Get-VMHost | ForEach-Object {
    $networkSystem = Get-View $_.ExtensionData.ConfigManager.NetworkSystem
    $dnsConfig = $networkSystem.NetworkConfig.DnsConfig
    
    [PSCustomObject]@{
        HostName = $_.Name
        Domain = $dnsConfig.Domain
        SearchDomains = $dnsConfig.SearchDomain -join ', '
        DNSServers = $dnsConfig.Address -join ', '
        DHCPEnabled = $dnsConfig.DhcpOnAnyVnic
    }
} | Format-Table -AutoSize