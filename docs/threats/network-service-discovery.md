# Network service discovery

## Metadata

- **UUID**: `fd0542bd-1541-42a7-8c07-0e073a198a53`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Network service discovery is the process of identifying and mapping
the services and applications running on a network. This can include
discovering open ports, protocols, and services, as well as identifying
the operating systems and devices connected to the network. Devices that
support NSD include printers, webcams, HTTPS servers, and other mobile
devices ref [1].  

Adversaries may attempt to get a listing of services running on remote hosts, 
including those that may be vulnerable to remote software exploitation. 
Methods to acquire this information include port scans and vulnerability 
scans, using tools that are brought onto a system.  

### Types of Network Service Discovery:

- Active Scanning: Sending probes to the network to gather information
about the services and devices connected.
- Passive Scanning: Monitoring network traffic to gather information
about the services and devices connected.
- OS Detection: Identifying the operating system and device type
connected to the network.

### Some of the tools which can be used for network service discovery:

- Nmap: A popular network scanning tool that can perform active and
passive scanning.
- Netcat - this tool is a command-line utility scanning tool across
network connections over TCP and UDP protocols. It scan ports, transfer
files, create chat servers, and perform HTTP requests ref [7].  
- MASSCAN - Internet-scale port scanner. It can scan the entire network
in a very short interval of time ref [8].   
- OpenVAS: A vulnerability scanner that can perform network service
discovery and identify potential vulnerabilities.
- Nessus: A vulnerability scanner that can perform network service
discovery and identify potential vulnerabilities.
- Wireshark: A network protocol analyzer that can be used to monitor
network traffic and identify services and devices connected.
- Netstat (net commands Windows): A command-line tool that can be used
to view active
network connections and listening ports.
- Native Bonjour application
- Intermapper tool: Stands out for its strong focus on visual network
discovery and mapping. A free 30-day trial is available on request.
- NetBrain: Goes beyond traditional network discovery tools, offering
a comprehensive solution for visualizing, managing, and automating
hybrid networks.

Example for such activity could be scan port in a specific ip and
port ranges.

## Techniques
- T1046

## Chaining
```mermaid
flowchart LR
fd0542bd_1541_42a7_8c07_0e073a198a53["Network service discovery"]
d5039f2c_9fcc_4ba3_ad6a_da8c891ba745["Abuse of Windows Utilities"]
fd0542bd_1541_42a7_8c07_0e073a198a53 --> d5039f2c_9fcc_4ba3_ad6a_da8c891ba745
```
