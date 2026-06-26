# Network service discovery

## Metadata

- **UUID**: `fd0542bd-1541-42a7-8c07-0e073a198a53`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-02-04`
- **Modified**: `2025-02-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://developer.android.com/training/connect-devices-wirelessly/nsd](https://developer.android.com/training/connect-devices-wirelessly/nsd)
- **2**: [https://en.wikipedia.org/wiki/Service_discovery](https://en.wikipedia.org/wiki/Service_discovery)
- **3**: [https://www.w3.org/TR/discovery-api/](https://www.w3.org/TR/discovery-api/)
- **4**: [https://www.servicenow.com/products/it-operations-management/what-is-network-discovery.html](https://www.servicenow.com/products/it-operations-management/what-is-network-discovery.html)
- **5**: [https://medium.com/@andrenogueira.dev/network-service-discovery-on-android-simplifying-device-communication-5de1d2d9996b](https://medium.com/@andrenogueira.dev/network-service-discovery-on-android-simplifying-device-communication-5de1d2d9996b)
- **6**: [https://www.bleepingcomputer.com/sysadmin/guides/best-network-discovery-tools/](https://www.bleepingcomputer.com/sysadmin/guides/best-network-discovery-tools/)
- **7**: [https://linuxize.com/post/netcat-nc-command-with-examples/](https://linuxize.com/post/netcat-nc-command-with-examples/)
- **8**: [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan)

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

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **An adversary is looking to exploit native system applications
or to use enumeration external tools in an attempt to find
an entry network point.

Domains: Enterprise, IoT, Mobile, Private Cloud, Public Cloud
Targets: End-user, Firewall, LAN, Laptop, Network Equipment, Router or switch, Workstations, Customer, Mobile phone, Peripheral, Web Application Servers, Other, Public-Facing Servers
Platforms: Active Directory, AWS VPC, Azure, Windows, Linux, macOS, Apache HTTP Server, Android, iOS, Network Router**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Localised incident | A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation. |
| Impact | Impairement; Lose Capabilities; Nuisance | - |
| Leverage | Dwelling; Infrastructure Compromise; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Discovery | Techniques that allow an attacker to gain knowledge about a system and its network environment. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Lazarus Group](https://attack.mitre.org/groups/G0032) | `att&ck::G0032` | ('att&ck',) | [Lazarus Group](https://attack.mitre.org/groups/G0032) is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.(Citation: US-CERT HIDDEN COBRA June 2017)(Citation: Treasury North Korean Cyber Groups September 2019) The group has been active since at least 2009 and was reportedly responsible for the November 2014 destructive wiper attack against Sony Pictures Entertainment as part of a campaign named Operation Blockbuster by Novetta. Malware used by [Lazarus Group](https://attack.mitre.org/groups/G0032) correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.(Citation: Novetta Blockbuster)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups, such as [Andariel](https://attack.mitre.org/groups/G0138), [APT37](https://attack.mitre.org/groups/G0067), [APT38](https://attack.mitre.org/groups/G0082), and [Kimsuky](https://attack.mitre.org/groups/G0094). |
| Lazarus Group | `misp::68391641-859f-4a9a-9a1e-3e5cf71ec376` | ('misp',) | Since 2009, HIDDEN COBRA actors have leveraged their capabilities to target and compromise a range of victims; some intrusions have resulted in the exfiltration of data while others have been disruptive in nature. Commercial reporting has referred to this activity as Lazarus Group and Guardians of Peace. Tools and capabilities used by HIDDEN COBRA actors include DDoS botnets, keyloggers, remote access tools (RATs), and wiper malware. Variants of malware and tools used by HIDDEN COBRA actors include Destover, Duuzer, and Hangman. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1046` | [Network Service Discovery](https://attack.mitre.org/techniques/T1046) | Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)     Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.  Within macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host’s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley) |

## Chaining
```mermaid
flowchart LR
fd0542bd_1541_42a7_8c07_0e073a198a53["Network service discovery"]
d5039f2c_9fcc_4ba3_ad6a_da8c891ba745["Abuse of Windows Utilities"]
fd0542bd_1541_42a7_8c07_0e073a198a53 -->|atomicity::implements| d5039f2c_9fcc_4ba3_ad6a_da8c891ba745
```
### Chaining details
#### implements -> Abuse of Windows Utilities (`atomicity::implements`)
Some of the build-in Windows utilities can be used
for network discovery. For example, net commands (net stat,
net config, net view, net user, net session and others).

- **Target UUID**: `d5039f2c-9fcc-4ba3-ad6a-da8c891ba745`
