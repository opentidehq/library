# DNS over HTTPS tunneling exfiltrates data or communicates to C&C server

## Metadata

- **UUID**: `901dd804-00cc-4034-85aa-3d10e257c16c`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2025-04-22`
- **Modified**: `2025-05-08`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.approach-cyber.com/blog-article/doh-cybersecurity-risk-in-enterprise/](https://www.approach-cyber.com/blog-article/doh-cybersecurity-risk-in-enterprise/)
- **2**: [https://quointelligence.eu/2021/02/dns-over-https-doh](https://quointelligence.eu/2021/02/dns-over-https-doh)
- **3**: [https://medium.com/@0xHossam/evading-detection-and-stealthy-data-exfiltration-with-dns-over-https-doh-ee134b5766d4](https://medium.com/@0xHossam/evading-detection-and-stealthy-data-exfiltration-with-dns-over-https-doh-ee134b5766d4)
- **4**: [https://medium.com/@scottbolen/mitre-attunes-spotlight-on-unc5221-decoding-chinas-apt-with-recent-attack-findings-2c3e7781c73b](https://medium.com/@scottbolen/mitre-attunes-spotlight-on-unc5221-decoding-chinas-apt-with-recent-attack-findings-2c3e7781c73b)
- **5**: [https://www.zdnet.com/article/dns-over-https-causes-more-problems-than-it-solves-experts-say](https://www.zdnet.com/article/dns-over-https-causes-more-problems-than-it-solves-experts-say)
- **6**: [https://www.csoonline.com/article/570867/understanding-doh-challenges-a-necessary-step-in-improving-network-privacy-and-security.html](https://www.csoonline.com/article/570867/understanding-doh-challenges-a-necessary-step-in-improving-network-privacy-and-security.html)

## Description
DNS over HTTPS (DoH) tunneling is a technique used by threat actors
to exfiltrate data or communicate to a Command and Control (C&C)
server. The data exchange and transfer between the victim and the
attacker's server can include - data exfiltration (stolen data) as
confidential documents or files, PIIs, financial data or intellectual
property. The data flow can be also an administrative traffic like
covert C&C communication, for example - chat or messaging traffic,
file (malicious payload) transfers, system control, manipulation
instructions and other possible signaling or instructions transfer.

DoH is a protocol that encrypts DNS requests and responses, making
it more difficult for third parties to intercept and manipulate DNS
traffic. However, threat actors have found a way to exploit this
protocol for malicious purposes ref [1].      

In a DoH tunneling attack, the threat actor uses the DoH protocol
to encapsulate malicious data, such as stolen credentials, sensitive
information, or malware, within DNS requests. The encrypted DNS requests
are then sent to a C&C server, which can be hosted on a compromised domain
or a domain controlled by the threat actor ref [2].    

A threat actor can use some of the following initial access techniques
or methods to perform DNS over HTTPS tunneling:   

- Compromises a device: Gains access to a victim's device, either through
phishing, exploiting vulnerabilities, or using malware.
- Installs malware: Installs malware on the compromised device, which can
be designed to collect sensitive information, such as login credentials
or personal data.
- Configures DoH: Configures the device to use DoH, either by modifying
the device's DNS settings or by installing a malicious DoH client.
- Encapsulates data: Encapsulates the stolen data within DNS requests,
using techniques such as:
- Data encoding: Encoding the data using techniques like Base64 or
hexadecimal encoding.
- Data fragmentation: Breaking the data into smaller fragments and
sending them across multiple DNS requests.
- Sends DNS requests: Sends the encrypted DNS requests to the C&C
server, which can be hosted on a compromised domain or a domain
controlled by the threat actor.
- Exfiltrates data: The C&C server receives the DNS requests, extracts
the encapsulated data, and stores or forwards it to the threat actor.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor can use DNS over HTTPS tunneling technique
to hide traffic and activities.

Domains: Enterprise
Targets: Control Server, Customer, Public-Facing Servers
Platforms: Windows, Network Router**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Impairement; Identity Theft; Data Breach; Operating costs; Reputational Damages | - |
| Leverage | Dwelling; Infrastructure Compromise; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Exfiltration | Techniques that result or aid in an attacker removing data from a target network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT3](https://attack.mitre.org/groups/G0022) | `att&ck::G0022` | ('att&ck',) | [APT3](https://attack.mitre.org/groups/G0022) is a China-based threat group that researchers have attributed to China's Ministry of State Security.(Citation: FireEye Clandestine Wolf)(Citation: Recorded Future APT3 May 2017) This group is responsible for the campaigns known as Operation Clandestine Fox, Operation Clandestine Wolf, and Operation Double Tap.(Citation: FireEye Clandestine Wolf)(Citation: FireEye Operation Double Tap) As of June 2015, the group appears to have shifted from targeting primarily US victims to primarily political organizations in Hong Kong.(Citation: Symantec Buckeye) |
| APT3 | `misp::d144c83e-2302-4947-9e24-856fbf7949ae` | ('misp',) | Symantec described UPS in  2016 report as: 'Buckeye (also known as APT3, Gothic Panda, UPS Team, and TG-0110) is a cyberespionage group that is believed to have been operating for well over half a decade. Traditionally, the group attacked organizations in the US as well as other targets. However, Buckeyes focus appears to have changed as of June 2015, when the group began compromising political entities in Hong Kong.' |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1572` | [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) | Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.   There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel.(Citation: SSH Tunneling)(Citation: Sygnia Abyss Locker 2025)   [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) may also be abused by adversaries during [Dynamic Resolution](https://attack.mitre.org/techniques/T1568). Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets.(Citation: BleepingComp Godlua JUL19)   Adversaries may also leverage [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) in conjunction with [Proxy](https://attack.mitre.org/techniques/T1090) and/or [Protocol or Service Impersonation](https://attack.mitre.org/techniques/T1001/003) to further conceal C2 communications and infrastructure. |
| `T1036` | [Masquerading](https://attack.mitre.org/techniques/T1036) | Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.  Renaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site) |
| `T1041` | [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) | Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications. |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
| `T1566` | [Phishing](https://attack.mitre.org/techniques/T1566) | Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.  Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source, as well as evasive techniques such as removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages (e.g., [Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008)).(Citation: Microsoft OAuth Spam 2022)(Citation: Palo Alto Unit 42 VBA Infostealer 2014) Another way to accomplish this is by [Email Spoofing](https://attack.mitre.org/techniques/T1672)(Citation: Proofpoint-spoof) the identity of the sender, which can be used to fool both the human recipient as well as automated security tools,(Citation: cyberproof-double-bounce) or by including the intended target as a party to an existing email thread that includes malicious files or links (i.e., "thread hijacking").(Citation: phishing-krebs)  Victims may also receive phishing messages that instruct them to call a phone number where they are directed to visit a malicious URL, download malware,(Citation: sygnia Luna Month)(Citation: CISA Remote Monitoring and Management Software) or install adversary-accessible remote management tools onto their computer (i.e., [User Execution](https://attack.mitre.org/techniques/T1204)).(Citation: Unit42 Luna Moth) |
