[CmdletBinding()]
Param (
    [string]$NetworkAddress = "192.168.0"
)
$HostName = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

# PID
$Processus = get-process | ?{$_.ID -eq $pid}
Write-Host "PID: $($Processus.Id)"
Write-Host "Network: $($NetworkAddress)"

# Fetch network interfaces of this host
$Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$True" | ? {$_.IPEnabled}
ForEach ($Network in $Networks) {
	If ($MAC.Length -ne 0)
	{
		New-Object PSObject -Property @{
			'Type'   = 'Network'
			'Host'   = $Network.DefaultIPGateway[0]
			'MAC'    = '-'
			'Vendor' = '-'
			'Info'   = "Mask=$($Network.IPSubnet[0]) DHCP=$($Network.DHCPEnabled) PrimaryDNS=$($Network.DNSServerSearchOrder[0])"
		}
	}
}

# Fetch this computer's interfaces
$Interfaces = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName $HostName -Filter "IpEnabled = TRUE"
foreach ($Interface in $Interfaces) {
	New-Object PSObject -Property @{
		'Type'   = 'ThisComputer'
		'Host'   = $Interface.IpAddress[0]
		'MAC'    = $Interface.MacAddress
		'Vendor' = '-'
		'Info'   = "HostName=$($HostName)"
	}
}

# Fetch ARP table
$Table = (arp -a | Select-String -Pattern "$NetworkAddress")
ForEach ($Entry in $Table)
{
	$Data = "$($Entry)".Trim() -split "\s+"
	$IP = $Data[0]
	$MAC = $Data[1]
	If ($MAC -eq ':' -Or $MAC -eq 'ff-ff-ff-ff-ff-ff') {
		Continue
	}
	$Whois = ''
	
	Try {
		$Ping = Get-WMIObject Win32_PingStatus -Filter "Address = '$($IP)' AND ResolveAddressNames = TRUE" -ErrorAction Stop
		If (!($Ping.StatusCode -eq 0))
		{
			$Whois = 'NotReachable'
		}
		else {
			$tmp = "$($Ping.ProtocolAddressResolved)"
			if (!($tmp -eq "") -And !($tmp -eq $IP)) {
				$Whois = "Resolve=$tmp"
			}
		}
	}
	Catch {
		$Whois = 'Resolve=PingError'
	}
	
	if ($Data[1] -eq $null) {
		$VendorPrefix = "?"
		$Vendor = "",""
	}
	else {
		$VendorPrefix = $Data[1].Substring(0, 8).ToUpper()
		$Vendor = Get-Content -Path "oui.txt" | Select-String $VendorPrefix -Context 0,0
		$Vendor = "$($Vendor)".Trim() -split "\s+"
	}
	New-Object PSObject -Property @{
		'Type'   = 'Peer'
		'Host'   = $IP
		'MAC'    = $MAC
		'Vendor' = $Vendor[2]
		'Info'   = $Whois
	}
}

Return

# Fetch IP addresses
Write-Host "NetworkAddressScan: $($NetworkAddress).*"
ForEach ($n in $Range)
{   

	# Current IP
	$IP = "{0}.{1}" -F $NetworkAddress,$n

	# Log
	#Write-Host "Working on $IP..."
	
	# Old
	<#
	If (!(Test-Connection -TimeToLive 1 -BufferSize 32 -Count 1 -Quiet -ComputerName $IP))
	#>
	
	# Ping IP address
    $Ping = Get-WMIObject Win32_PingStatus -Filter "Address = '$IP' AND ResolveAddressNames = TRUE" -ErrorAction Stop
	
	# Address not reachable
    If (!($Ping.StatusCode -eq 0))
    {
		New-Object PSObject -Property @{
			'Address' = $IP
			'Host' = 'Not Reachable'
			'MAC' = ''
		}
		Continue
	}

	$tmp = (arp -a | Select-String -Pattern "$IP")
	$tmp = "$($tmp)".Trim() -split "\s+"
	$MAC = $tmp[1]
	
	New-Object PSObject -Property @{
		'Address' = $IP
		'Host' = $Ping.ProtocolAddressResolved
		'MAC' = $MAC
	}
		
	# Try to resolve
	#Write-Host "$IP resolved to $($Ping.ProtocolAddressResolved)"
	
	#$colItems = Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -ComputerName $IP -Filter "IpEnabled = TRUE"
	#ForEach ($objItem in $colItems) {
	#	write-host $objItem.Description
	#	write-host "MAC Address: " $objItem.MacAddress
	#	write-host "IP Address: " $objItem.IpAddress
	#}
	
	# Ask RPC service
	<#Try {
		
		$Adapters = Get-WmiObject Win32_NetworkAdapter -Filter "NetEnabled = True" -ComputerName $Ping.ProtocolAddressResolved -ErrorAction Stop
		# Fetch network adapters
		ForEach ($Adapter in $Adapters)
		{   
			$Config = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "Index = $($Adapter.Index)" -ComputerName $Ping.ProtocolAddressResolved
			ForEach ($IPAddr in $Config.IPAddress)
			{
				New-Object PSObject -Property @{
					'IP Address' = $IPAddr
					'Host' = $Ping.ProtocolAddressResolved
					#'Interface Name' = $Adapter.Name
					'MAC Address' = $Config.MACAddress
				}
			}
		}
	}
	Catch {
		#Write-Error "WMI error accessing $($Ping.ProtocolAddressResolved)"
		#Write-Error $Error[1]
		New-Object PSObject -Property @{
			'IP Address' = $IP
			'Host' = $Ping.ProtocolAddressResolved
			'MAC Address' = '?'
		}
	}#>

}