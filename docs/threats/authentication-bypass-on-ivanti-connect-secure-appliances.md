# authentication bypass on Ivanti Connect Secure appliances

## Metadata

- **UUID**: `810057c6-cb84-41e4-add4-ae56b52c8ab7`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2024-01-15`
- **Modified**: `2024-01-29`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/)
- **2**: [https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis?referrer=etrblog](https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis?referrer=etrblog)
- **3**: [https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation](https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation)
- **4**: [https://www.mandiant.com/resources/blog/investigating-ivanti-exploitation-persistence](https://www.mandiant.com/resources/blog/investigating-ivanti-exploitation-persistence)

## Description
### chained exploitation of CVE-2023-46805 or CVE-2024-21893 together with CVE-2024-21887.

Attackers may chain exploits on vulnerabilities CVE-2023-46805 and 
CVE-2024-21893 on Ivanti Connect Secure (ICS) appliances (that provide 
remote VPN access to corporate infrastructures) to fully compromise the 
vulnerale appliance.  

The code on the appliance checks whether access to the requested uri_path 
requires authentication or not. For endpoint `/api/v1/totp/user-backup-code` 
the check is done only on the start of the string.  

So an attacker can append additional characters that are passed to the 
webserver without additional checks. Using path traversal technique, it is 
then possible to access API endpoints that would require authentication 
when accessed directly. For example, successful request to 
`/api/v1/totp/user-backup-code/../../system/system-information` will return
the system information.  

CVE-2023-46805 allows then to access any other uri_path without 
authentication and enables exploitation of CVE-2024-21887.

Later it was reported that initial mitigations for CVE-2023-46805 could be 
by passed by exploiting CVE-2024-21893 to bypass authentication and 
enabling CVE-2024-21887 without using vulnerable uri paths or to drop 
custom webshells ([BUSHWALK](https://advantage.mandiant.com/malware/malware--96732cf0-d99a-501b-9646-c49f2b30dd5a) 
[LIGHTWIRE](https://advantage.mandiant.com/malware/malware--089bf6cc-9b67-5bd5-8fd3-3330e7cedf7e) 
[CHAINLINE](https://advantage.mandiant.com/malware/malware--4a3560fd-5ec5-5581-a8f7-1c888d28186b) 
and others have been observed.  

Exploitation of the SSRF generates up to 2 log events:
- AUT31556 on `/dana-ws/saml.ws`
- ERR31093: Program saml-server recently failed. 

Likewise, exploition of CVE-2024-21893 or CVE-2024-22024 enables 
exploitation of CVE-2024-21887.

### Other TTPs

- *Configuration and data theft* Exfiltration of configuration or cache 
data either in the response to the request (so on apparently legit activity)
or by replacing or creating a new file under unauthenticated uri path.
- CAV Web Server Log Exfiltration 
- Internal Check tool tampering
- System log clearing: In some instances, logs have been cleared using the legitimate system 
utility therefore generating event ID ADM20599.

## Criticality
**Severe** - A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties.

## Terrain
> **Ivanti Connect Secure appliance vulnerable to authentication bypass (CVE-2023-46805)

Domains: Embedded, Enterprise, Networking
Cve: CVE-2023-46805, CVE-2024-21888, CVE-2024-21893, CVE-2024-22024
Targets: Remote access, VPN Client
Platforms: Placeholder**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Highly significant incident | A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy. |
| Impact | Business disruption; Operating costs; Reputational Damages; Data Breach | - |
| Leverage | Infrastructure Compromise; Elevation of privilege; Log tampering; Modify configuration; Tampering; New Accounts | - |
| Viability | Almost certain | Nearly certain - 95-99% |
| Kill Chain | Exploitation | Techniques to exploit vulnerabilities in systems that may, amongst others, result in code execution. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| Gelsemium | `misp::2dd31182-bae1-48ed-8bb3-805a3df89783` | ('misp',) | The Gelsemium group has been active since at least 2014 and was described in the past by a few security companies. Gelsemium’s name comes from one possible translation ESET found while reading a report from VenusTech who dubbed the group 狼毒草 for the first time. It’s the name of a genus of flowering plants belonging to the family Gelsemiaceae, Gelsemium elegans is the species that contains toxic compounds like Gelsemine, Gelsenicine and Gelsevirine, which ESET choses as names for the three components of this malware family. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1011` | [Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011) | Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.  Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network. |
| `T1041` | [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) | Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications. |
| `T1070` | [Indicator Removal](https://attack.mitre.org/techniques/T1070) | Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.  Removal of these indicators may interfere with event collection, reporting, or other processes used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred. |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
