# GSM interception

## Metadata

- **UUID**: `5238718b-13c4-46d7-a84c-d29c77e5d801`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-04-16`
- **Modified**: `2025-04-16`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://arstechnica.com/tech-policy/2013/09/meet-the-machines-that-steal-your-phones-data/](https://arstechnica.com/tech-policy/2013/09/meet-the-machines-that-steal-your-phones-data/)
- **2**: [https://blog.telco-sec.com/gsm-vulnerabilities-attack-vectors](https://blog.telco-sec.com/gsm-vulnerabilities-attack-vectors)
- **3**: [https://bluegoatcyber.com/blog/cybersecurity-vulnerabilities-with-gsm/](https://bluegoatcyber.com/blog/cybersecurity-vulnerabilities-with-gsm/)
- **4**: [https://www.sciencedirect.com/topics/computer-science/interception-attack](https://www.sciencedirect.com/topics/computer-science/interception-attack)

## Description
GSM interception refers to the unauthorized capture and monitoring of communications 
(calls, SMS, and sometimes data) transmitted over GSM (Global System for Mobile Communications) 
networks. This threat vector exploits inherent weaknesses in the GSM protocol, outdated 
encryption algorithms, and the ability to impersonate legitimate network infrastructure.

## How GSM interception works

**Key Techniques:**

- **IMSI Catchers (Fake Base Stations):** Attackers deploy rogue base stations 
(often called IMSI catchers or Stingrays) that mimic legitimate cell towers. Mobile 
devices in the vicinity connect to these fake towers, allowing attackers to capture 
the International Mobile Subscriber Identity (IMSI), track users, and intercept communications.

- **Weak Encryption Algorithms:** Early GSM encryption standards, such as A5/1 and 
A5/2, are now considered weak and can be cracked with modest resources. Attackers 
can eavesdrop on calls and SMS by decrypting intercepted radio signals.

- **Man-in-the-Middle (MitM) Attacks:** By placing themselves between the mobile 
device and the legitimate network, attackers can intercept, alter, or inject communications, 
often without the user’s knowledge.

- **Signaling Exploits:** Vulnerabilities in GSM’s signaling protocols (like SS7) 
can be abused to redirect calls or SMS messages to an attacker, enabling interception 
even if the attacker is not physically near the target.

## Threat impact

- **Eavesdropping:** Attackers can listen to phone calls and read SMS messages, 
compromising user privacy and potentially exposing sensitive or confidential information.

- **Location Tracking:** By capturing IMSI and other identifiers, attackers can 
track a user’s movements in real time.

- **Data Manipulation:** In MitM scenarios, attackers can alter messages or inject 
malicious content during transmission.

- **Fraud and Identity Theft:** Intercepted communications can be used for social 
engineering, phishing, or unauthorized access to accounts (e.g., intercepting SMS-based 
two-factor authentication).

## Real-world examples

- **Commercial Surveillance Devices:** Commercially available devices can intercept 
GSM traffic, extract encryption keys, and monitor communications. These devices 
are used by law enforcement, intelligence agencies, and sometimes by criminals to 
conduct surveillance or steal information.

- **Notorious Attacks:** There have been documented cases where attackers used GSM 
interception to gain access to bank accounts by intercepting SMS-based authentication codes.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries need specialized hardware such as passive or active GSM interceptors 
(e.g., IMSI catchers, fake base stations). These devices can mimic legitimate cell 
towers and force nearby mobile phones to connect, enabling interception of communications.

Domains: Mobile
Targets: Tablet, Mobile phone, Personal Information, Critical Documents
Platforms: Android, iOS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Identity Theft; IP Loss; Nuisance; Reputational Damages | - |
| Leverage | Dwelling; Hardware tampering; Information Disclosure; Infrastructure Compromise; Spoofing | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Collection | Techniques used to identify and gather data from a target network prior to exfiltration. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1638` | [Mobile : Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) | Adversaries may attempt to position themselves between two or more networked devices to support follow-on behaviors such as [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002) or [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1642).       [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) can be achieved through several mechanisms. For example, a malicious application may register itself as a VPN client, effectively redirecting device traffic to adversary-owned resources. Registering as a VPN client requires user consent on both Android and iOS; additionally, a special entitlement granted by Apple is needed for iOS devices. Alternatively, a malicious application with escalation privileges may utilize those privileges to gain access to network traffic.       Specific to Android devices, adversary-in-the-disk is a type of AiTM attack where adversaries monitor and manipulate data that is exchanged between applications and external storage.(Citation: mitd_kaspersky)(Citation: mitd_checkpoint)(Citation: mitd_checkpoint_research) To accomplish this, a malicious application firsts requests for access to multimedia files on the device (`READ_EXTERNAL STORAGE` and `WRITE_EXTERNAL_STORAGE`), then the application reads data on the device and/or writes malware to the device. Though the request for access is common, when used maliciously, adversaries may access files and other sensitive data due to abusing the permission. Multiple applications were shown to be vulnerable against this attack; however, scrutiny of permissions and input validations may mitigate this attack.      Outside of a mobile device, adversaries may be able to capture traffic by employing a rogue base station or Wi-Fi access point. These devices will allow adversaries to capture network traffic after it has left the device, while it is flowing to its destination. On a local network, enterprise techniques could be used, such as [ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) or [DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003).       If applications properly encrypt their network traffic, sensitive data may not be accessible to adversaries, depending on the point of capture. For example, properly implementing Apple’s Application Transport Security (ATS) and Android’s Network Security Configuration (NSC) may prevent sensitive data leaks.(Citation: NSC_Android) |
| `T1040` | [Network Sniffing](https://attack.mitre.org/techniques/T1040) | Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.  Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.  Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and/or [Defense Evasion](https://attack.mitre.org/tactics/TA0005) activities. Adversaries may likely also utilize network sniffing during [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) (AiTM) to passively gain additional knowledge about the environment.  In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to.(Citation: AWS Traffic Mirroring)(Citation: GCP Packet Mirroring)(Citation: Azure Virtual Network TAP) Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic.(Citation: Rhino Security Labs AWS VPC Traffic Mirroring)(Citation: SpecterOps AWS Traffic Mirroring) The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic.(Citation: Rhino Security Labs AWS VPC Traffic Mirroring)  On network devices, adversaries may perform network captures using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `monitor capture`.(Citation: US-CERT-TA18-106A)(Citation: capture_embedded_packet_on_software) |
| `T1589` | [Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589) | Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations.  Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about users could also be enumerated via other active means (i.e. [Active Scanning](https://attack.mitre.org/techniques/T1595)) such as probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA /methods associated with those usernames.(Citation: GrimBlog UsernameEnum)(Citation: Obsidian SSPR Abuse 2023) Information about victims may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: OPM Leak)(Citation: Register Deloitte)(Citation: Register Uber)(Citation: Detectify Slack Tokens)(Citation: Forbes GitHub Creds)(Citation: GitHub truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks)  Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)). |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
