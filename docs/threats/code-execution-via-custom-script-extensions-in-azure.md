# Code execution via custom script extensions in Azure

## Metadata

- **UUID**: `61ddc240-e5a6-4ca8-ae77-6b471b498913`
- **Schema**: `threat::1.0`
- **Version**: `3`
- **Created**: `2025-05-15`
- **Modified**: `2025-09-08`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-azure-with-custom-script-extensions/](https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-azure-with-custom-script-extensions/)
- **2**: [https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows)
- **3**: [https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors](https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors)

## Description
The Azure Custom Script Extension (CSE) is designed to automate post-deployment 
tasks on virtual machines (VMs) by downloading and executing scripts provided by 
users. While this is intended for legitimate configuration and management, it introduces 
a powerful threat vector: attackers with sufficient Azure permissions can leverage 
CSE to execute arbitrary code as SYSTEM (Windows) or root (Linux) on any accessible VM.

### How Attackers Exploit This Vector

- **Privilege Abuse**: If an attacker compromises an account with the *Virtual Machine 
Contributor* role or any role that grants `Microsoft.Compute/virtualMachines/extensions/write` 
permissions, they can deploy or update custom script extensions on target VMs.
- **Arbitrary Code Execution**: The attacker can specify any script (PowerShell, Bash, etc.) 
to be downloaded from a remote location (such as a malicious website or public repository) 
and executed with the highest local privileges on the VM.
- **Bypassing Network Controls**: Because CSE operates through the Azure control 
plane, it does not require direct network access to the VM. Scripts can be executed 
even if RDP or SSH ports are closed, bypassing traditional network-based restrictions.
- **Persistence and Lateral Movement**: Attackers can use CSE to establish persistence 
(e.g., by installing backdoors), harvest credentials, or pivot to other resources 
within the environment.
- **Stealth**: Since CSE operations are part of normal Azure VM management workflows, 
malicious activity may blend in with legitimate administrative actions.

### Example Attack Scenario
- An attacker uploads a malicious script to a public storage location.
- Using compromised credentials with the necessary Azure permissions, the attacker 
configures the CSE on a target VM to download and execute the script.
- The script runs as SYSTEM/root, granting full control over the VM, and can perform 
actions such as installing malware, mining cryptocurrency, exfiltrating data, or 
creating new privileged accounts.

### Real-World Impact
- **Observed Cases**: There have been documented incidents where attackers used 
the CSE to deploy cryptocurrency miners across multiple customer environments by 
referencing a malicious script hosted on a public GitHub repository.
- **Scope of Access**: This technique is not limited to individual VMs; it can be 
used on VM scale sets and Azure ARC-managed resources, amplifying the potential impact.
- **No Network Barriers**: The attack is effective regardless of the VM’s network 
security group settings or firewall rules, as it leverages the Azure management plane.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries must have an Azure role that grants the ability to write or deploy custom 
script extensions on virtual machines.

Domains: Public Cloud, Enterprise
Targets: Virtual Machines, Cloud Storage Accounts, Compute Cluster, Public-Facing Servers, Serverless, API Endpoints, Cloud Portal, IaaS, Server Authentication, Server Backup, Server Logs
Platforms: Azure, Windows, Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Monetary Loss; Lose Capabilities; Business disruption | - |
| Leverage | Elevation of privilege; Information Disclosure; Infrastructure Compromise; Tampering; Spoofing | - |
| Viability | Very Likely | Highly probable - 80-95% |
| Kill Chain | Execution | Techniques that result in execution of attacker-controlled code on a local or remote system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1555` | [Credentials from Password Stores](https://attack.mitre.org/techniques/T1555) | Adversaries may search for common password storage locations to obtain user credentials.(Citation: F-Secure The Dukes) Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information. |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
| `T1204` | [User Execution](https://attack.mitre.org/techniques/T1204) | An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of [Phishing](https://attack.mitre.org/techniques/T1566).  While [User Execution](https://attack.mitre.org/techniques/T1204) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).  Adversaries may also deceive users into performing actions such as:  * Enabling [Remote Access Tools](https://attack.mitre.org/techniques/T1219), allowing direct control of the system to the adversary * Running malicious JavaScript in their browser, allowing adversaries to [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539)s(Citation: Talos Roblox Scam 2023)(Citation: Krebs Discord Bookmarks 2023) * Downloading and executing malware for [User Execution](https://attack.mitre.org/techniques/T1204) * Coerceing users to copy, paste, and execute malicious code manually(Citation: Reliaquest-execution)(Citation: proofpoint-selfpwn)  For example, tech support scams can be facilitated through [Phishing](https://attack.mitre.org/techniques/T1566), vishing, or various forms of user interaction. Adversaries can use a combination of these methods, such as spoofing and promoting toll-free numbers or call centers that are used to direct victims to malicious websites, to deliver and execute payloads containing malware or [Remote Access Tools](https://attack.mitre.org/techniques/T1219).(Citation: Telephone Attack Delivery) |

## Chaining
```mermaid
flowchart LR
61ddc240_e5a6_4ca8_ae77_6b471b498913["Code execution via custom script extensions in Azure"]
140907eb_c9fb_4330_9d71_656422388b2b["Azure - Gather Role Information"]
2743bf18_3b86_4721_bf3e_153dcda0b149["Azure - Valid Credentials"]
61ddc240_e5a6_4ca8_ae77_6b471b498913 -->|support::enabled| 140907eb_c9fb_4330_9d71_656422388b2b
140907eb_c9fb_4330_9d71_656422388b2b -->|support::enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
```
### Chaining details
#### enabled -> Azure - Gather Role Information (`support::enabled`)
Adversaries need to identify privileged accounts and misconfigured role assignments 
that can be exploited for privilege escalation.

- **Target UUID**: `140907eb-c9fb-4330-9d71-656422388b2b`
#### enabled -> Azure - Valid Credentials (`support::enabled`)
Adversaries obtain the username and password of an AzureAD user either through phishing, 
password spraying, brute-force attacks, or credentials leaked online.

- **Target UUID**: `2743bf18-3b86-4721-bf3e-153dcda0b149`
