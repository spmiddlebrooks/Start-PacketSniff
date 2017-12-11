<#
.SYNOPSIS
	A .Net based PowerShell packet sniffer ("promiscuous mode" must be supported by hardware/driver)
.DESCRIPTION
.PARAMETER
.EXAMPLE
	Start-PacketSniff [-LocalIP <String>] [-IpAddressFilter <String>] [-ProtocolFilter <String>] [-PortFilter <String>] [-DscpFilter <String>] [-Seconds <Int32>] [-ResolveHosts]
	Start-PacketSniff | %{'{0}:{1}->{2}:{3}' -f $_.sourceip,$_.sourceport,$_.destinationip,$_.destinationport}
.NOTES
	Version: 2.0
	Updated: 7/24/2017
	Original Author: Sven Sperner (Git Hub: sperner; Email: cethss@gmail.com)
	Updates Author : Scott Middlebrooks
.LINK
	Original Source - https://github.com/sperner/PowerShell/blob/master/Sniffer.ps1
#>
#Requires -Version 3.0

[cmdletbinding()]
param( 
	[Parameter(Mandatory=$False)]
		[String] $LocalIP = "NotSpecified", 
	[Parameter(Mandatory=$False)]
		[String] $IpAddressFilter="All", 
	[Parameter(Mandatory=$False)]
		[ValidateSet('TCP|UDP','TCP','UDP')]
		[String] $ProtocolFilter = "TCP|UDP", `
	[Parameter(Mandatory=$False)]
		[ValidateScript({
			$_ -match "^(All|\d{1,5}|\d{1,5}:\d{1,5})$"
		})]
		[String] $PortFilter="All", 
	[Parameter(Mandatory=$False)]
		[ValidateScript({
			$_ -match "^(All|\d{1,2}|\d{1,2}:\d{1,2})$"
		})]
		[string] $DscpFilter="All", 
	[Parameter(Mandatory=$False)]
		[Int] $Seconds = 0, 
	[Parameter(Mandatory=$False)]
		[switch] $ResolveHosts
)

# Params
$starttime = Get-Date
$escKey = 27
$qKey = 81
$running = $true

$byteTrue = New-Object Byte[] 4			# source
$byteData = New-Object Byte[] 1024000	# size of data

$byteTrue = @(1, 0, 0, 0)				# enable promiscuous mode

# Convert from big to little endian & convert to uint16
Function Convert-NetworkToHostUInt16( $address ) {
	[Array]::Reverse( $address )
	return [BitConverter]::ToUInt16( $address, 0 )
}

# Convert from big to little endian & convert to uint32
Function Convert-NetworkToHostUInt32( $address ) {
	[Array]::Reverse( $address )
	return [BitConverter]::ToUInt32( $address, 0 )
}

$DnsResolveCache = @{} 	# Array for hostnames that have already been resolved
# Get IP-address <-> hostname
Function Get-DnsHostName( $IPAddress ) {
	if( $HostName = $DnsResolveCache."$($IPAddress.IPAddressToString)" )
	{
		if( $IPAddress.IPAddressToString -eq $HostName )
		{
			# Unable to resolve the IP Address to a hostname in a previous attempt, so just return the IP address
			return [IPAddress]$IPAddress
		}
		else
		{
			# Hostname found in $DnsResolveCache, return $HostName
			return $HostName
		}
	}
	else
	{	
		if	( $HostName = [string] (Resolve-DnsName -DnsOnly $IPAddress.IPAddressToString -ErrorAction SilentlyContinue).NameHost ) {
			# Resolved the IP Address to a Hostname, store that in the $DnsResolveCache and return the $HostName
			$DnsResolveCache."$($IPAddress.IPAddressToString)" = "$HostName"
			return $HostName
		}
		else {
			# Unable to resolve the IP Address to a hostname, store the IP Address in the $DnsResolveCache and return the IP Address
			$DnsResolveCache."$($IPAddress.IPAddressToString)" = "$($IPAddress.IPAddressToString)"
			return $IPAddress
		}
	}
}

function Convert-TosToDscp {
param (
	[int] $TosValue
)

	switch ($TosValue) {
		0		{ $DscpValue = 0 }
		4		{ $DscpValue = 1 }
		8		{ $DscpValue = 2 }
		12		{ $DscpValue = 3 }
		16		{ $DscpValue = 4 }		
		default { $DscpValue = ((($TosValue - 32) / 8) * 2) + 8}
	}
	return $DscpValue
}

# Get local IP-Address
if( $LocalIP -eq "NotSpecified" ) {
	$LocalIP = (Find-NetRoute -RemoteIPAddress 0.0.0.0).IPAddress
	$LocalIP = $LocalIP.Trim()
}
Write-Verbose "Local IP: $LocalIP"

# Open a raw ip socket
$Socket = New-Object System.Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP )
# Include the ip header
$Socket.SetSocketOption( "IP", "HeaderIncluded", $true )
# Big packet buffer
$Socket.ReceiveBufferSize = 1024000
# Create ip endpoint
$Endpoint = New-Object System.Net.IPEndpoint( [IPAddress]"$LocalIP", 0 )
$Socket.Bind( $Endpoint )
# Enable promiscuous mode
[void]$Socket.IOControl( [Net.Sockets.IOControlCode]::ReceiveAll, $byteTrue, $byteTrue )

Write-Host "Press ESC or Q key to stop the packet sniffer ...`n" -Foreground yellow
# Start sniffing
while( $running ) {
	# when a key was pressed...
	if( $host.ui.RawUi.KeyAvailable ) {
		$key = $host.ui.RawUI.ReadKey( "NoEcho,IncludeKeyUp,IncludeKeyDown" )
		# if ESC was pressed, stop sniffing
		if( $key.VirtualKeyCode -eq $ESCkey -or $key.VirtualKeyCode -eq $qKey ) {
			$running = $false
		}
	}
	# Stop sniffing after $Seconds...
	if( $Seconds -ne 0 -and ((Get-Date) -gt $starttime.addseconds($Seconds)) ) {
		exit
	}
	# no packets in card buffer...
	if( -not $Socket.Available ) {
		start-sleep -milliseconds 300
		continue
	}
	
	# receive data
	$rData = $Socket.Receive( $byteData, 0, $byteData.length, [Net.Sockets.SocketFlags]::None )
	# decode the packet
	$MemoryStream = New-Object System.IO.MemoryStream( $byteData, 0, $rData )
	$BinaryReader = New-Object System.IO.BinaryReader( $MemoryStream )

	# b1 - version & header length
	$VerHL = $BinaryReader.ReadByte( )
	# b2 - type of service
	$TOS= $BinaryReader.ReadByte( )
	# b3,4 - total length
	$Length = Convert-NetworkToHostUInt16 $BinaryReader.ReadBytes( 2 )
	# b5,6 - identification
	$Ident = Convert-NetworkToHostUInt16 $BinaryReader.ReadBytes( 2 )
	# b7,8 - flags & offset
	$FlagsOff = Convert-NetworkToHostUInt16 $BinaryReader.ReadBytes( 2 )
	# b9 - time to live
	$TTL = $BinaryReader.ReadByte( )
	# b10 - protocol
	$ProtocolNumber = $BinaryReader.ReadByte( )
	# b11,12 - header checksum
	$Checksum = [IPAddress]::NetworkToHostOrder( $BinaryReader.ReadInt16() )
	# b13-16 - source ip address
	[IPAddress] $SourceIP = $BinaryReader.ReadUInt32( )
	# b17-20 - destination ip address
	[IPAddress] $DestinationIP = $BinaryReader.ReadUInt32( )

	$sourcePort = Convert-NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
	$destPort = Convert-NetworkToHostUInt16 $BinaryReader.ReadBytes(2)	
	
	switch( $ProtocolNumber ) {
		6		{ $ProtocolDesc = "TCP" }
		17		{ $ProtocolDesc = "UDP" }
		default { $ProtocolDesc = "Other" }
	}
	
	$BinaryReader.Close( )
	$memorystream.Close( )

	# resolve IP addresses to hostnames...
	if( $ResolveHosts ) {
		$DestinationHostName = Get-DnsHostName( $DestinationIP )
		$SourceHostName = Get-DnsHostName( $SourceIP )
	}

	$Dscp = Convert-TosToDscp $TOS

	if ($PortFilter -match "^\d{1,5}:\d{1,5}$") {
		[int]$PortStart,[int]$PortEnd = $PortFilter -split ':'
	}
	if ($DscpFilter -match "^\d{1,2}:\d{1,2}$") {
		[int]$DscpStart,[int]$DscpEnd = $DscpFilter -split ':'
	}

	if ($ProtocolDesc -match $ProtocolFilter) {
		if( ($PortFilter -eq "All") -or ($PortFilter -eq $sourcePort) -or ($PortFilter -eq $destPort) -or ($sourceport -in $PortStart..$PortEnd) -or ($destinationport -in $PortStart..$PortEnd)) {
			if( ($DscpFilter -eq "All") -or ($DscpFilter -eq $Dscp) -or ($Dscp -in $DscpStart..$DscpEnd) ) {
				if( ($IpAddressFilter -eq "All") -or ($IpAddressFilter -eq $SourceIp) -or ($IpAddressFilter -eq $DestinationIP) ) {
					$Output = [PsCustomObject] @{
						DateTime = $(Get-Date -Format s)
						Protocol = $ProtocolDesc
						SourceHostName = $SourceHostName
						SourceIP = $SourceIP
						SourcePort = $sourcePort
						DestinationHostName = $DestinationHostName
						DestinationIp = $DestinationIP
						DestinationPort = $destPort
						DSCP = $Dscp
					}
		
					$Output
				}
			}
		}
	}
}
