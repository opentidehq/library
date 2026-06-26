# Host information gathering in Linux systems

## Metadata

- **UUID**: `4f0f3e9c-8d61-422c-9c13-809aa75cab59`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-08-06`
- **Modified**: `2025-08-07`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.geeksforgeeks.org/linux-unix/kali-linux-information-gathering-tools](https://www.geeksforgeeks.org/linux-unix/kali-linux-information-gathering-tools)
- **2**: [https://www.redhat.com/en/blog/linux-system-info-commands](https://www.redhat.com/en/blog/linux-system-info-commands)
- **3**: [https://medium.com/@velmuruganofficial/top-15-advanced-and-best-information-gathering-tools-67f07550e502](https://medium.com/@velmuruganofficial/top-15-advanced-and-best-information-gathering-tools-67f07550e502)
- **4**: [https://www.geeksforgeeks.org/linux-unix/sparta-tool-in-kali-linux](https://www.geeksforgeeks.org/linux-unix/sparta-tool-in-kali-linux)

## Description
Host information gathering in Linux can be a part of a reconnaissance
process, allowing threat actors to understand the target system details and
configuration, collect valuable information and identify potential
vulnerabilities on the host.  

### Possible information gathering on Linux system

- A hostname and domain name - a threat actor may use the `hostname` command
  to retrieve the system's hostname and domain name.
- IP address: usage of `ip addr` or `ifconfig` commands can retrieve the
  system's IP address. The IP address of the system is a valuable piece of
  information for future collection and reconnaissance activities.
- Network interface configuration: the command `ip link` or `ifconfig` is
  used to retrieve information about network interfaces, including IP
  addresses, subnet masks, and default gateways.
- Operating system and version: a threat actor can use `uname -a` or
  `cat /etc/os-release` command to retrieve information about the operating
  system and its version. A command like `uname` can display information
  about the system, for example the kernel name, version, and the Linux
  architecture.  
- Kernel Version: with the command `uname -r` an attacker can retrieve the
  kernel version of a targeted system.
- CPU architecture: a threat actor may use the `uname -m` command to
  retrieve the CPU architecture. A threat actor may also use `lscpu` on Linux
  to gather CPU's capabilities like model information, number of cores,
  speeds, flags, virtualisation capabilities and other CPU related
  parameters ref [3]. 
- Memory and disk information: an attacker can use `-m` and `df -h` commands
  to retrieve information about memory and disk usage. With other commands
  like `df`, `fdisk`, or `mount` they can check the system storage and to
  find the disks attached to the system ref [2], [3].  
- Whois lookup: a threat actor can perform the command `whois` <domain_name>
  to retrieve which are the registered domains in the database record on
  the host.
- Name server lookup: a threat actor can use `nslookup` on Linux to get the
  information from a DNS server. It queries DNS to obtain a domain name, IP
  address mapping, or any other DNS record. This coomand can be used for a
  system gathering of information. 
- Environment variables: `env` or `printenv` can expose environment
  variables, which might include credentials, proxy settings, or session-
  related tokens useful for further exploitation.
- Running processes and services: commands like `ps aux`, `top` can help a
  threat actor to identify active processes and services, which may reveal
  misconfigured applications or listening services.
- Scheduled jobs: `crontab -l`, `cat /etc/crontab`, or reviewing
  `/etc/cron.*` directories can uncover automated tasks or persistence
  mechanisms.
- Listening ports and services: `ss -tuln` or `netstat -tuln` can show
  services listening on the host, along with the associated ports and
  protocols.  
  
### Known tools used for Linux information gathering

- Nmap: A network scanning tool that can be used to gather information about
  open ports and services.
- LinEnum: A tool that can be used to gather information about Linux
  systems, including user and group information.
- Zenmap - it's a network discovery and security auditing tool
- SPARTA - tool used in the scanning and enumeration phase of information
  gathering on Linux systems. This tool can be used for network scanning and
  collection of information, for example scan of IP ranges, network and
  domain names ref [4].

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor needs an initial access to a Linux system.

Domains: Enterprise
Targets: Laptop, Workstations
Platforms: Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Data Breach; Identity Theft | - |
| Leverage | Information Disclosure | Threat action intending to read a file that one was not granted access to, or to read data in transit. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Reconnaissance | Researching, identifying and selecting targets using active or passive reconnaissance. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1082` | [System Information Discovery](https://attack.mitre.org/techniques/T1082) | An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.  Tools such as [Systeminfo](https://attack.mitre.org/software/S0096) can be used to gather detailed system information. If running with privileged access, a breakdown of system data can be gathered through the <code>systemsetup</code> configuration tool on macOS. As an example, adversaries with user-level access can execute the <code>df -aH</code> command to obtain currently mounted disks and associated freely available space. Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather detailed system information (e.g. <code>show version</code>).(Citation: US-CERT-TA18-106A) On ESXi servers, threat actors may gather system information from various esxcli utilities, such as `system hostname get`, `system version get`, and `storage filesystem list` (to list storage volumes).(Citation: Crowdstrike Hypervisor Jackpotting Pt 2 2021)(Citation: Varonis)  Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.(Citation: Amazon Describe Instance)(Citation: Google Instances Resource)(Citation: Microsoft Virutal Machine API)  [System Information Discovery](https://attack.mitre.org/techniques/T1082) combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment.(Citation: OSX.FairyTale)(Citation: 20 macOS Common Tools and Techniques) |
