# Installing a Domain Controller with Server 2019 Core

## Core Network Planning Sheet

More info can be found at [docs.microsoft.com](https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/core-network-guide).

### Pre-installation configuration items for AD DS and DNS

| Configuration items | Value |
| --- | --- |
| Computer Name DC | `dc-str-1` |
| IPv4 network | `10.55.200.0` |
| IPv4 subnet mask | `/22` (`255.255.252.0`) |
| IPv4 host address | `10.55.200.10` |
| IPv4 primary DNS server | `10.55.200.10` (dc-str-1) |
| IPv4 default gateway | `10.55.200.1` |
| IPv6 network | `2a02:8070:89b7:2ef1::` |
| IPv6 subnet mask | `/64` |
| IPv6 host address | `2a02:8070:89b7:2ef1::10` |
| IPv6 primary DNS server | `2a02:8070:89b7:2ef1::10` (dc-str-1) |
| IPv6 default gateway | `2a02:8070:89b7:2ef1::1` |

### AD DS and DNS installation configuration items

| Configuration items | Value |
| --- | --- |
| Full DNS name | `raw.blackrockbrawlers.com` |
| Forest functional level | Windows Server 2016 (`7` or WinThreshold) |
| Directory Restore Mode Administrator password | `034Kasld*%yyVA!msdfadf` (example only) |
| Active Directory Domain Services database folder location | default location |
| Active Directory Domain Services log files folder location | default location |
| Active Directory Domain Services SYSVOL folder location | default location |

### Configuring a DNS Reverse Lookup Zone

| Configuration items | Value |
| --- | --- |
| Zone type | Primary zone |
| Store the zone in Active Directory | yes |
| Active Directory zone replication scope | To all DNS servers in this domain |
| Reverse lookup zone name | IPv4 Reverse Lookup Zone (IP Type) `10.55.200` (network ID) |
| Dynamic Updates | Allow only secure dynamic updates |

### DHCP installation configuration items

| Configuration items | Value |
| --- | --- |
| Network connect bindings | Ethernet |
| DNS server settings | `dc-str-1` |
| Preferred DNS server IP address | `10.55.200.10` (dc-str-1) |
| Alternate DNS server IP address | `10.55.200.11` (dc-str-2) (if second DC exists) |
| Scope name | `Intranet` |
| Starting IP address | `10.55.203.1` |
| Ending IP address | `10.55.203.254` |
| Subnet mask | `255.255.252.0` |
| Default gateway | `10.55.200.1` |
| DNS parent domain | `raw.blackrockbrawlers.com` |
| Lease duration | 8 days |

## Setup

### Initial Configuration

Necessary steps:

* Configure and run Windows Updates (use `sconfig` tool)
* Configure static IP address
* Rename computer
* Set TimeZone
* Restart host

Run `powershell`.

#### Time zone data

Verify and update timezone data:

```powershell
# get currently active timezone
Get-TimeZone
# find timezone id
Get-TimeZone -Name "*euro*"
# set timezone
Set-TimeZone -Id "W. Europe Standard Time"
```

#### Network Interface

Locate the Nic card you want to set up IP information for by running.

```powershell
Get-NetAdapter
PS C:\Users\Administrator> Get-NetAdapter
Name                      InterfaceDescription                    ifIndex Status       MacAddress             LinkSpeed
----                      --------------------                    ------- ------       ----------             ---------
Ethernet0                 Intel(R) 82574L Gigabit Network Conn...       6 Up           00-0C-29-0A-02-FE         1 Gbps
```

Use the name of the adapter as the interfaceAlias (here `Ethernet0`).

You can rename a network adapter (optional):

```powershell
# rename network adapter 'Ethernet0'
Rename-NetAdapter -Name "Ethernet0" -NewName "LAN"
```

#### Configuration

Setup ip address, hostname and dns:

```powershell
$hostname = "dc-str-1"
$interface = "LAN"
$ipaddress = "10.55.200.10"
$gateway = "10.55.200.1"
$ipaddress6 = "2a02:8070:89b7:2ef1::10"
$gateway6 = "2a02:8070:89b7:2ef1::1"
# disable DHCP on LAN
Set-NetIPInterface -InterfaceAlias $interface -DHCP Disabled -PassThru
# set new IPv4 address for NIC
New-NetIPAddress -InterfaceAlias $interface -AddressFamily IPv4 -IPAddress $ipaddress -PrefixLength 22 -DefaultGateway $gateway
# TODO: set new IPv6 address for NIC
New-NetIPAddress -InterfaceAlias $interface -AddressFamily IPv6 -IPAddress $ipaddress6 -PrefixLength 64 -DefaultGateway $gateway6
# set primary dns server for NIC
Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses $ipaddress,$ipaddress6 -PassThru
# rename host and restart
Rename-Computer -NewName $hostname -Restart -Force -PassThru
```

### Install AD DS and DNS

Run in `powershell` after rebooting:

```powershell
$domain = "raw.blackrockbrawlers.com"
$netbios = "RAW"
# Install AD DS feature
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
# Promote server to DC
Install-ADDSForest `
  -DomainName $domain `
  -DomainNetbiosName $netbios `
  -DomainMode "7" `
  -ForestMode "7" `
  -InstallDns:$true `
  -NoRebootOnCompletion:$false `
  -Force:$true
# This reboots the system upon completion
```

### Configure NTP

Run in `powershell` after rebooting:

```powershell
w32tm /config /manualpeerlist:"0.de.pool.ntp.org,0x9 1.de.pool.ntp.org,0x9 2.de.pool.ntp.org,0x9" /syncfromflags:manual /reliable:yes /update
net stop w32time; net start w32time
# sync now
w32tm /resync
# verify last sync time
w32tm /query /status
```

### Configure DNS

#### Configure a DNS Reverse Lookup Zone

Get list of configured DNS zones with `Get-DnsServerZone`.

```powershell
$network = "10.55.200.0"
$netmask = "22"
$network6 = "2a02:8070:89b7:2ef1::"
$netmask6 = "64"
Add-DnsServerPrimaryZone -NetworkID $network/$netmask -ReplicationScope Domain -DynamicUpdate Secure -PassThru
Add-DnsServerPrimaryZone -NetworkID $network6/$netmask6 -ReplicationScope Domain -DynamicUpdate Secure -PassThru
# register DNS-server in its zone by rebooting or running the next command
ipconfig /registerdns
```

#### Configure DNS resolution

```powershell
$interface = "LAN"
$ipaddress = "10.55.200.10"
$ipaddress6 = "2a02:8070:89b7:2ef1::10"
$gateway = "10.55.200.1"
$gateway6 = "2a02:8070:89b7:2ef1::1"
# revert automatic dns server change to the server's external ip address
Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses $ipaddress,$ipaddress6
# check name resolution
nslookup
# setup forwarders for names which are unknown to this domain
Set-DnsServerForwarder -IPAddress $gateway,$gateway6
```

#### Configure zone scavenging and aging

```powershell
# TODO: check this values and compare with that one blog article
Set-DnsServerScavenging -ScavengingState:$true `
  -ScavengingInterval 4.00:00:00 `
  -RefreshInterval 3.00:00:00 `
  -NoRefreshInterval 0 `
  -ApplyOnAllZones `
  -PassThru
```

### DHCP

#### Preparation

Create a service account for dhcp server.

`345sdASNnren5sdnfjgDNFJLSFJ(ODnskd!!!!dsfsdfmvndjkehtPOdisyyxv`

```powershell
# create new OU 'Service Accounts'
New-ADOrganizationalUnit `
  -Name "Service Accounts" `
  -Path "DC=raw,DC=blackrockbrawlers,DC=com" `
  -PassThru
New-ADUser `
  -SamAccountName "sa_dhcp" `
  -name "SA_DHCP" `
  -AccountPassword (read-host "Set service password" -assecurestring) `
  -PasswordNeverExpires:$true `
  -ChangePasswordAtLogon:$false `
  -Path "OU=Service Accounts,DC=raw,DC=blackrockbrawlers,DC=com" `
  -enabled:$true
```

Install DHCP Server ([source](https://docs.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-deploy-wps)):

```powershell
$fqn = "dc-str-1.raw.blackrockbrawlers.com"
$dnsDomain = "raw.blackrockbrawlers.com"
$ipaddress = "10.55.200.10"
$gateway = "10.55.200.1"
$rangeStart = "10.55.203.1"
$rangeEnd = "10.55.203.254"
$subnetmask = "255.255.252.0"
$network = "10.55.200.0"
# Install feature
Install-WindowsFeature DHCP -IncludeManagementTools
# Create DHCP security groups
netsh dhcp add securitygroups
# Restart DHCP service
Restart-Service dhcpserver
# Authorize DHCP server in active directory
Add-DhcpServerInDC -DnsName $fqn -IPAddress $ipaddress
# Check if DHCP server is authorized (output shouldn't be empty)
Get-DhcpServerInDC
# Notify Server Manager that post-install DHCP configuration is complete
Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
# Set server level DNS dynamic update configuration settings
Set-DhcpServerv4DnsSetting -ComputerName $fqn -DynamicUpdates "Always" -DeleteDnsRRonLeaseExpiry $True
# Set credential for DHCP server
Set-DhcpServerDnsCredential -ComputerName $fqn
# Configure the Intranet Scope
Add-DhcpServerv4Scope -name "Intranet" -StartRange $rangeStart -EndRange $rangeEnd -SubnetMask $subnetmask -State Active
# Set default gateway
Set-DhcpServerv4OptionValue -OptionID 3 -Value $gateway -ScopeID $network -ComputerName $fqn
# Set default dns server
Set-DhcpServerv4OptionValue -DnsDomain $dnsDomain -DnsServer $ipaddress
# TODO: lookup mor concise Set-DhcpServerv4OptionValue
# TODO: set dhcpv6 setting
$ipaddress6 = "2a02:8070:89b7:2ef1::10"
$prefix = "2a02:8070:89b7:2eff::"
$rangeStart6 = "2a02:8070:89b7:2eff::1"
$rangeEnd6 = "2a02:8070:89b7:2eff::ff"
# Add IPv6 ip scope
Add-DhcpServerv6Scope -name "Intranet IPv6" -Prefix $prefix -State Active -PassThru
# Exclude first /120 network for internal use
Add-DhcpServerv6ExclusionRange `
  -Prefix $prefix `
  -StartRange $rangeStart6 `
  -EndRange $rangeEnd6 `
  -PassThru
# Configure DNS server and domain search list
Set-DhcpServerv6OptionValue `
  -Prefix $prefix `
  -DnsServer $ipaddress6 `
  -DomainSearchList $dnsDomain `
  -PassThru
```

## Administration

### Check Windows Updates

Use the `sconfig` tool.

### Create a User Account in Active Directory Users and Computers

Create a default user account which, by default, is granted membership to the Domain Users group.

```powershell
New-ADUser `
  -SamAccountName "chris.rock" `
  -AccountPassword (read-host "Set user password" -assecurestring) `
  -name "Chris Rock" `
  -enabled $true `
  -PasswordNeverExpires $true `
  -ChangePasswordAtLogon $false
```

Assign additional group memberships for the new user account granting membership to the Domain Admins and Enterprise Admins groups group.

```powershell
Add-ADPrincipalGroupMembership `
  -Identity "CN=Chris Rock,CN=Users,DC=raw,DC=blackrockbrawlers,DC=com" `
  -MemberOf "CN=Enterprise Admins,CN=Users,DC=raw,DC=blackrockbrawlers,DC=com","CN=Domain Admins,CN=Users,DC=raw,DC=blackrockbrawlers,DC=com"
```

### Joining Client Computers to the Domain and Logging On

```powershell
Rename-Computer -NewName "ws-str-01" -Restart
# after reboot
Add-Computer -DomainName "raw.blackrockbrawlers.com" -Restart
```

## Install all RSAT tools on a Windows 10 1809 client

Run this code in an elevated powershell console:

```powershell
Get-WindowsCapability -Online -Name RSAT* | Add-WindowsCapability -Online
```

## Lab Setup

Use three VMs within VMware Workstation:

1. pfsense/opnsense Router (`gw`)
1. Windows Server 2019 DC (`dc-str-1`)
1. Windows 10 v1809 Client (`ws-str-01`)

VMware Workstation has a `VMnet10` of type `Host-only` with disabled DHCP server (configured via `Virtual Network Editor`).

### Router

Router has two network interfaces:

1. WAN NIC is in bridge/nat mode to the host's network
2. LAN NIC is `VMnet10` and thus isolated from host's network

### Server

The Windows Server's primary NIC is connected to `VMnet10`.

### Client

The Windows 10's primary NIC is connected to `VMnet10`.

## Complete Script

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

# AD
$adHostname = "dc-str-1"
$adDomain   = "raw.blackrockbrawlers.com"
$adNetbios  = "RAW"
$adFQN      = "$adHostname.$adDomain"
$adSafeModeAdministratorPassword = ConvertTo-SecureString -String 'RandomAndVeeeryLongADRestorePassword34*%VA!' -AsPlainText -Force

# OU, Users and Credentials
$adBaseDN      = $adDomain.Split(".").Foreach({('DC=' + $_)}) -join ","
$adResourcesDN = "OU=Resources," + $adBaseDN
$adOUsToCreate = "Admin Users", "Groups Security", "Service Accounts", "Workstations", "Servers", "Users"

# Network
# Get the primary Network Adapter's Prefix
$netInterfaceIndex = (Get-NetAdapter).ifIndex
$netInterfaceName = "LAN"
# IPv4
$net4Ipaddress    = "10.55.200.10"
$net4Gateway      = "10.55.200.1"
$net4Network      = "10.55.200.0"
$net4PrefixLength = 22
# IPv6
$net6Ipaddress    = "2a02:8070:89b7:2ef1::10"
$net6Gateway      = "2a02:8070:89b7:2ef1::1"
$net6Network      = "2a02:8070:89b7:2ef1::"
$net6PrefixLength = 64

# DHCP IPv4
$dhcpSamAccountNameDNSUpdateServiceUser = "sa_dhcp"
$dhcpDNSUpdateServiceUser = ConvertTo-SecureString -String 'RandomAndVeeeryLongServiceAccountPassword!?8%8' -AsPlainText -Force
$dhcp4RangeStart = "10.55.203.1"
$dhcp4RangeEnd   = "10.55.203.254"
$dhcp4Subnetmask = "255.255.252.0"
# DHCP IPv6
$dhcp6RangeStart = "2a02:8070:89b7:2eff::1"
$dhcp6RangeEnd   = "2a02:8070:89b7:2eff::ff"

$ntpManualPeerList = "0.de.pool.ntp.org,0x9 1.de.pool.ntp.org,0x9 2.de.pool.ntp.org,0x9"

# Rename vm's default network interface
if ((Get-NetAdapter).Name -eq "Ethernet0") {
  echo "[NET] Renaming network adapter 'Ethernet0' into '$netInterfaceName'"
  Rename-NetAdapter -Name "Ethernet0" -NewName $netInterfaceName
}

# First run until reboot because of hostname change
if ((Get-ComputerInfo).CsName -ne $adHostname) {
  echo "[INF] Running initial system configuration"
  # Set timezone
  Set-TimeZone -Id "W. Europe Standard Time"
  echo "[CFG] Set system's timezone to 'W. Europe Standard Time'"
  # Disable DHCP on interface LAN
  Set-NetIPInterface -InterfaceIndex $netInterfaceIndex -DHCP Disabled | Out-Null
  echo "[NET] Disabled DHCP on primary NIC"
  # Set new IPv4 address for NIC
  New-NetIPAddress `
    -InterfaceIndex $netInterfaceIndex `
    -AddressFamily IPv4 `
    -IPAddress $net4Ipaddress `
    -PrefixLength $net4PrefixLength `
    -DefaultGateway $net4Gateway
  echo "[NET] Configured static IPv4 address on primary NIC"
  # Set new IPv6 address for NIC
  New-NetIPAddress `
    -InterfaceIndex $netInterfaceIndex `
    -AddressFamily IPv6 `
    -IPAddress $net6Ipaddress `
    -PrefixLength $net6PrefixLength `
    -DefaultGateway $net6Gateway
  echo "[NET] Configured static IPv6 address on primary NIC"
  # Turn off IPv6 Random & Temporary IP Assignments
  Set-NetIPv6Protocol -RandomizeIdentifiers Disabled
  Set-NetIPv6Protocol -UseTemporaryAddresses Disabled
  # Turn off IPv6 Transition Technologies
  Set-Net6to4Configuration -State Disabled
  Set-NetIsatapConfiguration -State Disabled
  Set-NetTeredoConfiguration -Type Disabled
  # Set primary dns servers for NIC which point to the DC server itself
  Set-DnsClientServerAddress -InterfaceIndex $netInterfaceIndex -ServerAddresses $net4Ipaddress,$net6Ipaddress
  echo "[NET] Configured dns servers on primary NIC"
  # Rename host and restart
  echo "[AD] Renaming system to '$adHostname'"
  Rename-Computer -NewName $adHostname -Force
  Restart-Computer -Force
  exit 0
}

# Second run until reboot because of AD forest installation
if ((Get-ComputerInfo).CsDomain -ne $adDomain) {
  echo "[AD] Installing Active Directory Services"
  # Install AD DS feature
  Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
  # Install AD Forest and reboot
  echo "[AD] Creating AD forest '$adDomain'"
  Install-ADDSForest `
    -DomainName $adDomain `
    -DomainNetbiosName $adNetbios `
    -DomainMode "WinThreshold" `
    -ForestMode "WinThreshold" `
    -SafeModeAdministratorPassword $adSafeModeAdministratorPassword `
    -InstallDns:$true `
    -NoRebootOnCompletion:$false `
    -Force:$true
  exit 0
}

# Configure upstream time servers for PDC
echo "[NTP] Adding upstream time servers"
w32tm /config /manualpeerlist:"$ntpManualPeerList" /syncfromflags:manual /reliable:yes /update | Out-Null
net stop w32time | Out-Null
net start w32time | Out-Null
# Sync now
w32tm /resync | Out-Null

# Configure a DNS reverse lookup zone
Add-DnsServerPrimaryZone -NetworkID "$net4Network/$net4PrefixLength" -ReplicationScope Forest -DynamicUpdate NonsecureAndSecure
Add-DnsServerPrimaryZone -NetworkID "$net6Network/$net6PrefixLength" -ReplicationScope Forest -DynamicUpdate NonsecureAndSecure
echo "[DNS] Registered primary zones"
# Register DNS-server in its zone by rebooting or running the next command
ipconfig /registerdns | Out-Null
# Revert automatic dns server change to the server's external ip address
Set-DnsClientServerAddress -InterfaceIndex $netInterfaceIndex -ServerAddresses $net4Ipaddress,$net6Ipaddress
echo "[NET] Configured DNS server to this server's external IP"
# Setup forwarders for names which are unknown to this domain
Set-DnsServerForwarder -IPAddress $net4Gateway,$net6Gateway
echo "[DNS] Added DNS forwarders"
# Enable automatic DNS scavenging of stale records TODO
Set-DnsServerScavenging -ScavengingState:$true `
  -ScavengingInterval 7.00:00:00 `
  -RefreshInterval 7.00:00:00 `
  -NoRefreshInterval 7.00:00:00 `
  -ApplyOnAllZones
echo "[DNS] Enabled scavenging of stale records"
# Primary AD and DNS settings are done

# Build an OU structure
New-ADOrganizationalUnit -Name "Resources" -Path $adBaseDN
foreach($ou in $adOUsToCreate) {
  New-ADOrganizationalUnit -Name $ou -Path $adResourcesDN
}
echo "[AD] Created organizational units"

echo "[INF] Installing DHCP server"
# Install DHCP feature
Install-WindowsFeature DHCP -IncludeManagementTools | Out-Null
echo "[DHCP] Installed DHCP server feature"
# Create DHCP security groups
netsh dhcp add securitygroups | Out-Null
# Restart DHCP service
Restart-Service dhcpserver | Out-Null
# Authorize DHCP server in active directory
Add-DhcpServerInDC
echo "[DHCP] Registered DHCP server in DC"
# Notify Server Manager that post-install DHCP configuration is complete
Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
# Set server level DNS dynamic update configuration settings
Set-DhcpServerv4DnsSetting -DynamicUpdates Always -DeleteDnsRRonLeaseExpiry:$true
# Configure the Intranet Scope
Add-DhcpServerv4Scope `
  -name "Intranet" `
  -StartRange $dhcp4RangeStart `
  -EndRange $dhcp4RangeEnd `
  -SubnetMask $dhcp4Subnetmask `
  -State Active
# Set Intranet scope settings
Set-DhcpServerv4OptionValue `
  -ScopeId $net4Network `
  -DnsServer $net4Ipaddress `
  -DnsDomain $adDomain `
  -Router $net4Gateway
echo "[DHCP] Created IPv4 Intranet scope"
# Add IPv6 ip scope
Add-DhcpServerv6Scope `
  -name "Intranet" `
  -Prefix $net6Network `
  -State Active
# Configure DNS server and domain search list
Set-DhcpServerv6OptionValue `
  -Prefix $net6Network `
  -DnsServer $net6Ipaddress `
  -DomainSearchList $adDomain
echo "[DHCP] Created IPv6 Intranet scope"
# Add AD user for DHCP+DNS-Update only
New-ADUser `
  -SamAccountName $dhcpSamAccountNameDNSUpdateServiceUser `
  -name $dhcpSamAccountNameDNSUpdateServiceUser.ToUpper() `
  -AccountPassword $dhcpDNSUpdateServiceUser `
  -PasswordNeverExpires:$true `
  -ChangePasswordAtLogon:$false `
  -Path "OU=Service Accounts,$adResourcesDN" `
  -enabled:$true
echo "[AD] Created service user '$dhcpSamAccountNameDNSUpdateServiceUser'"
# Set credential for DHCP server
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$adNetbios\$dhcpSamAccountNameDNSUpdateServiceUser",$dhcpDNSUpdateServiceUser
Set-DhcpServerDnsCredential -Credential $cred
echo "[DHCP] Registered credentials for service user '$dhcpSamAccountNameDNSUpdateServiceUser' in DHCP server"
# Secure DHCP server co-located on DC
dnscmd /config /OpenAclOnProxyUpdates 0 | Out-Null
Add-ADGroupMember "DnsUpdateProxy" ($adHostname.ToUpper() + "$")

# protect AD objects from accidential deletion
Enable-ADOptionalFeature –Identity 'Recycle Bin Feature' –Scope ForestOrConfigurationSet –Target $adDomain -Server $adFQN -confirm:$false
echo "[AD] Enabled 'Recycle Bin Feature'"
```

## Create User Accounts

### Create a Privileged Account

```powershell
$user = @{
  Name                  = "Chris Rock"
  GivenName             = "Chris"
  Surname               = "Rock"
  DisplayName           = "Chris Rock"
  Path                  = "OU=Admin Users,OU=Resources,DC=raw,DC=blackrockbrawlers,DC=com"
  SamAccountName        = "chris.rock"
  UserPrincipalName     = "chris.rock@raw.blackrockbrawlers.com"
  AccountPassword       = (read-host "Set user password" -assecurestring)
  PasswordNeverExpires  = $true
  ChangePasswordAtLogon = $false
  Enabled               = $true
  Description           = "RAW Enterprise Admin"
}
New-ADUser @user
# Add Privileged Account to EA, DA, & SA Groups
Add-ADGroupMember "Domain Admins" $user.SamAccountName
Add-ADGroupMember "Enterprise Admins" $user.SamAccountName
Add-ADGroupMember "Schema Admins" $user.SamAccountName
```

### Create a Non-Privileged User Account

```powershell
$user = @{
  Name                  = "Pink Pop"
  GivenName             = "Ping"
  Surname               = "Pop"
  DisplayName           = "Pink Pop"
  Path                  = "OU=Users,OU=Resources,DC=raw,DC=blackrockbrawlers,DC=com"
  SamAccountName        = "pink.pop"
  UserPrincipalName     = "pink.pop@raw.blackrockbrawlers.com"
  AccountPassword       = (read-host "Set user password" -assecurestring)
  PasswordNeverExpires  = $true
  ChangePasswordAtLogon = $false
  Enabled               = $true
  Description           = "RAW User"
}
New-ADUser @user
```

## Resources

* [Lab Setup Domain Controller with powershell](https://itpro.outsidesys.com/2015/12/13/lab-build-a-domain-controller-with-powershell/)
* [DNS/DHCP/Scavenging](https://blogs.msmvps.com/acefekay/2016/08/13/dynamic-dns-updates-how-to-get-it-to-work-with-dhcp-scavenging-static-entries-their-timestamps-the-dnsupdateproxy-group-and-dhcp-name-protection/)
* [Deploy AD DS and DNS](https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/core-network-guide)
* [Deploy DHCP](https://docs.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-deploy-wps)
* [Install DC with Server 2016 Core](https://blogs.technet.microsoft.com/chadcox/2016/10/25/chads-quick-notes-installing-a-domain-controller-with-server-2016-core/)
* [IPv6 im Windows-Netz](https://www.heise.de/ix/heft/Anschub-2197665.html)
* [DHCPv6 Stateful on Windows Server 2019 and ArubaOS-Switch](https://youtu.be/riQyXbxu0xo)
