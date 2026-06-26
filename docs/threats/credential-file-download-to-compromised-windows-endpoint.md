# Credential file download to compromised Windows endpoint

## Metadata

- **UUID**: `94b7287b-ae84-4b89-8093-63898c7475c9`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-03-12`
- **Modified**: `2025-03-12`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://blog.bitsadmin.com/extracting-credentials-from-remote-windows-system](https://blog.bitsadmin.com/extracting-credentials-from-remote-windows-system)
- **2**: [https://www.elastic.co/guide/en/security/8.17/potential-file-transfer-via-curl-for-windows.html](https://www.elastic.co/guide/en/security/8.17/potential-file-transfer-via-curl-for-windows.html)
- **3**: [https://www.nirsoft.net/utils/remote_desktop_password.html](https://www.nirsoft.net/utils/remote_desktop_password.html)
- **4**: [https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details/](https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details/)
- **5**: [https://serverfault.com/questions/770996/where-does-credential-manager-store-credentials-on-the-file-system](https://serverfault.com/questions/770996/where-does-credential-manager-store-credentials-on-the-file-system)
- **6**: [https://www.proofpoint.com/us/blog/threat-insight/whatta-ta-ta505-ramps-activity-delivers-new-flawedgrace-variant](https://www.proofpoint.com/us/blog/threat-insight/whatta-ta-ta505-ramps-activity-delivers-new-flawedgrace-variant)
- **7**: [https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta505-dridex-globeimposter](https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta505-dridex-globeimposter)
- **8**: [https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage](https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage)
- **9**: [https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/leafminer-espionage-middle-east)

## Description
A credential file download to Windows compromised endpoint
refers to a process where an attacker downloads sensitive
credential files to this system. A threat actor usually
target to download files containing passwords, authentication
tokens, or other sensitive information. Threat actors may use
remote tools to download Windows credential files and to
extract their content if its decrypted ref [1], [2].  

### Methods used by the threat actors

Threat actors may use various methods to download credential files,
for example:

- SMB (Server Message Block) exploitation: Attackers may exploit
vulnerabilities in SMB to gain access to the compromised endpoint
and download credential files.
- PowerShell scripts: Attackers may use PowerShell scripts to
download credential files from the compromised endpoint.
- Remote Desktop Protocol (RDP): Attackers may use RDP to gain
access to the compromised endpoint and download credential files.
- Malware: Attackers may use malware to download credential files
from the compromised endpoint.
- Curl for Windows (via HTTP requests) - Adversaries could abuse
`Curl` to download files or upload data to a remote URL address
ref [2].  
- Remote Desktop PassView - this tool can access Windows credential
files via .rdp files. It's possible such file to contain user's
credentials ref [3]. 

### Known types of files which may contain user's credentials 

The following types of credential files may be downloaded by the
attackers through a compromised network:

- SAM (Security Account Manager) files: These files contain hashed
passwords for local user accounts.
- NTDS.DIT files: These files contain hashed passwords for Active
Directory user accounts.
- Credential Manager files: These files contain stored credentials
for applications and services.
- SSH key files: These files contain private SSH keys used for
authentication.  

### An example 

Threat actors can download and use the accessed credential user's
files to connect to a database further, without having to enter
login credentials each time they access the database. The database
system will authenticate their login based on the information
stored in the credential file.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires an already compromised Windows endpoint.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: Desktop, Workstations, Control Server, Laptop, Production Database, End-user, Remote access
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft; Lose Capabilities; Nuisance; Reputational Damages | - |
| Leverage | Tampering; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] TA505](https://attack.mitre.org/groups/G0092) | `att&ck::G0092` | ('att&ck',) | [TA505](https://attack.mitre.org/groups/G0092) is a cyber criminal group that has been active since at least 2014. [TA505](https://attack.mitre.org/groups/G0092) is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaigns involving [Clop](https://attack.mitre.org/software/S0611).(Citation: Proofpoint TA505 Sep 2017)(Citation: Proofpoint TA505 June 2018)(Citation: Proofpoint TA505 Jan 2019)(Citation: NCC Group TA505)(Citation: Korean FSI TA505 2020) |
| TA505 | `misp::03c80674-35f8-4fe0-be2b-226ed0fcd69f` | ('misp',) | TA505, the name given by Proofpoint, has been in the cybercrime business for at least four years. This is the group behind the infamous Dridex banking trojan and Locky ransomware, delivered through malicious email campaigns via Necurs botnet. Other malware associated with TA505 include Philadelphia and GlobeImposter ransomware families. |
| [[Enterprise] Leafminer](https://attack.mitre.org/groups/G0077) | `att&ck::G0077` | ('att&ck',) | [Leafminer](https://attack.mitre.org/groups/G0077) is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017. (Citation: Symantec Leafminer July 2018) |
| RASPITE | `misp::2c8994ba-367c-46f6-bfb0-390c8760dd9e` | ('misp',) | Dragos has identified a new activity group targeting access operations in the electric utility sector. We call this activity group RASPITE.  Analysis of RASPITE tactics, techniques, and procedures (TTPs) indicate the group has been active in some form since early- to mid-2017. RASPITE targeting includes entities in the US, Middle East, Europe, and East Asia. Operations against electric utility organizations appear limited to the US at this time.  RASPITE leverages strategic website compromise to gain initial access to target networks. RASPITE uses the same methodology as DYMALLOY and ALLANITE in embedding a link to a resource to prompt an SMB connection, from which it harvests Windows credentials. The group then deploys install scripts for a malicious service to beacon back to RASPITE-controlled infrastructure, allowing the adversary to remotely access the victim machine. |
| [[Enterprise] APT33](https://attack.mitre.org/groups/G0064) | `att&ck::G0064` | ('att&ck',) | [APT33](https://attack.mitre.org/groups/G0064) is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors.(Citation: FireEye APT33 Sept 2017)(Citation: FireEye APT33 Webinar Sept 2017) |
| APT33 | `misp::4f69ec6d-cb6b-42af-b8e2-920a2aa4be10` | ('misp',) | Our analysis reveals that APT33 is a capable group that has carried out cyber espionage operations since at least 2013. We assess APT33 works at the behest of the Iranian government. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1552.001` | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001) | Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.  It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003).(Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.(Citation: SRD GPP)  In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files.(Citation: Unit 42 Hildegard Malware) They may also be found as parameters to deployment commands in container logs.(Citation: Unit 42 Unsecured Docker Daemons) In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.(Citation: Specter Ops - Cloud Credential Storage) |
| `T1555.004` | [Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004) | Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults).(Citation: Microsoft Credential Manager store)(Citation: Microsoft Credential Locker)  The Windows Credential Manager separates website credentials from application or network credentials in two lockers. As part of [Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003), Internet Explorer and Microsoft Edge website credentials are managed by the Credential Manager and are stored in the Web Credentials locker. Application and network credentials are stored in the Windows Credentials locker.  Credential Lockers store credentials in encrypted `.vcrd` files, located under `%Systemdrive%\Users\\[Username]\AppData\Local\Microsoft\\[Vault/Credentials]\`. The encryption key can be found in a file named <code>Policy.vpol</code>, typically located in the same folder as the credentials.(Citation: passcape Windows Vault)(Citation: Malwarebytes The Windows Vault)  Adversaries may list credentials managed by the Windows Credential Manager through several mechanisms. <code>vaultcmd.exe</code> is a native Windows executable that can be used to enumerate credentials stored in the Credential Locker through a command-line interface. Adversaries may also gather credentials by directly reading files located inside of the Credential Lockers. Windows APIs, such as <code>CredEnumerateA</code>, may also be absued to list credentials managed by the Credential Manager.(Citation: Microsoft CredEnumerate)(Citation: Delpy Mimikatz Crendential Manager)  Adversaries may also obtain credentials from credential backups. Credential backups and restorations may be performed by running <code>rundll32.exe keymgr.dll KRShowKeyMgr</code> then selecting the “Back up...” button on the “Stored User Names and Passwords” GUI.  Password recovery tools may also obtain plain text passwords from the Credential Manager.(Citation: Malwarebytes The Windows Vault) |
