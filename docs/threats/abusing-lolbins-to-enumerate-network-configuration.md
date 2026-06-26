# Abusing Lolbins to Enumerate Network Configuration

## Metadata

- **UUID**: `fc858766-0618-4a4f-973c-526402a83582`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
System Network Configuration Discovery refers to an adversary’s effort to gather
and enumerate network-related information from compromised systems. This activity 
is often a precursor to more aggressive tactics, including lateral movement 
or data exfiltration. By executing commands or employing specific utilities to 
determine active network interfaces, routing tables, firewall states, and open ports, 
threat actors can map out an organization’s network architecture. 
This information allows them to identify potential choke points, pivot opportunities, 
and security gaps that could be exploited in subsequent stages of an attack.

## Common Tools & Commands
### Windows  

1) cmd.exe:
  - `ipconfig` to display IP addresses and network interfaces. 
  - `netstat` to list active TCP/UDP connections and listening ports.
  - `route print` to display routing tables.  

2) powershell.exe: 
  - `Get-NetIPConfiguration` to display IP addresses and network interfaces. 
  - `Get-NetTCPConnection` to display active network connections.
  - `Get-NetRoute` to display routing tables.  

3) netsh.exe: 
  - `netsh interface ip show config` for advanced interface information. 
  - `netsh interface ip show dns` to display DNS settings.

4) nslookup.exe: 
  - `nslookup <domain_name>` to display DNS records for a domain name. 

5) wmic.exe: 
  - `wmic nic get` to display network interface settings.
  - `wmic route get` to display routing tables.

### Linux and macOS 
  - `ifconfig` or `ip` to show IP address configuration and network interfaces.  
  - `arp` to examine the ARP table for link-layer address mapping.  
  - `netstat` or `ss` to display active connections and listening services.  
  - `route` to view or modify the IP routing table.  
  - `iptables`, `firewall-cmd`, `ufw` to query or adjust firewall settings.  
  - `dig` to query DNS servers and display DNS records.

## Techniques
- T1016
