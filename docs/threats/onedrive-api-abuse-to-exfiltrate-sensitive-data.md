# OneDrive API abuse to exfiltrate sensitive data

## Metadata

- **UUID**: `10663f4a-6432-4c8f-bd3a-eaa599bb474e`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-06-25`
- **Modified**: `2025-06-25`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.paloaltonetworks.com/blog/security-operations/detecting-threats-with-microsoft-graph-activity-logs/](https://www.paloaltonetworks.com/blog/security-operations/detecting-threats-with-microsoft-graph-activity-logs/)
- **2**: [https://www.scworld.com/news/embargo-lifts-6-am-eastern-august-7-symantec-points-to-rise-in-attacks-on-cloud-infrastructure](https://www.scworld.com/news/embargo-lifts-6-am-eastern-august-7-symantec-points-to-rise-in-attacks-on-cloud-infrastructure)

## Description
OneDrive API abuse to exfiltrate sensitive data occurs when attackers misuse legitimate 
Microsoft Graph API endpoints and OneDrive’s cloud storage features to steal confidential 
or sensitive information from an organization.

### How Does It Work?

1. **API Exploitation via Microsoft Graph**
  - Attackers use the Microsoft Graph API to access users’ OneDrive storage.
  - Common endpoints include:
    - `https://graph.microsoft.com/v1.0/users/{id}/drive` (to list drives)
    - `https://graph.microsoft.com/v1.0/drive/items/{item-id}/content` (to download files)
  - These APIs are normally used for legitimate cloud storage operations.

2. **OAuth and Application Permissions**
  - Attackers may compromise existing OAuth applications or create new ones.
  - By granting these applications broad permissions (like “Files.Read.All” or 
  “Files.ReadWrite.All”), attackers gain access to OneDrive files without direct 
  user interaction.

3. **Use of Trusted Cloud Services**
  - Data exfiltration is carried out through OneDrive, a trusted and widely used 
  cloud service.
  - This makes malicious activity harder to distinguish from normal business operations.

4. **Automated Exfiltration**
  - Attackers often use scripts or malware to automate the process of accessing 
  and transferring files via OneDrive.
  - This allows for large-scale, stealthy data theft.

### Attack Scenarios

- **Compromised Credentials:** An attacker gains access to an account with OneDrive 
API permissions.
- **Malicious OAuth App:** An attacker registers an OAuth app with excessive permissions 
and uses it to access OneDrive files.
- **Automated Scripts:** Attackers use PowerShell or other scripting tools to interact 
with the OneDrive API, extracting sensitive files at scale.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries need an authenticated user or application identity (such as a compromised 
user account or a maliciously registered OAuth application) with the necessary permissions 
to access OneDrive files. And also, API permissions (like “Files.Read.All” or “Files.ReadWrite.All”) 
that allow reading or downloading files from OneDrive via the Microsoft Graph API.

Domains: Public Cloud, SaaS, Enterprise
Targets: Cloud Storage Accounts, Personal Information, Production Database, Identity Services, Public-Facing Servers, API Endpoints, Cloud Portal
Platforms: Office 365, Azure AD**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Monetary Loss | - |
| Leverage | Information Disclosure; Tampering; Spoofing; Elevation of privilege | - |
| Viability | Likely | Probable (probably) - 55-80% |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
| `T1534` | [Internal Spearphishing](https://attack.mitre.org/techniques/T1534) | After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization. Internal spearphishing is multi-staged campaign where a legitimate account is initially compromised either by controlling the user's device or by compromising the account credentials of the user. Adversaries may then attempt to take advantage of the trusted internal account to increase the likelihood of tricking more victims into falling for phish attempts, often incorporating [Impersonation](https://attack.mitre.org/techniques/T1656).(Citation: Trend Micro - Int SP)  For example, adversaries may leverage [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) or [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through [Input Capture](https://attack.mitre.org/techniques/T1056) on sites that mimic login interfaces.  Adversaries may also leverage internal chat apps, such as Microsoft Teams, to spread malicious content or engage users in attempts to capture sensitive information and/or credentials.(Citation: Int SP - chat apps) |
