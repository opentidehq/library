# Windows explorer used to search for files with credentials

## Metadata

- **UUID**: `78d80d14-7260-44b8-95e9-6cf3693b0024`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-03-10`
- **Modified**: `2025-03-12`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.tipsdotcom.com/how-to-search-for-files-in-windows-10.html](https://www.tipsdotcom.com/how-to-search-for-files-in-windows-10.html)
- **2**: [https://pureinfotech.com/access-network-shared-folder-windows-11](https://pureinfotech.com/access-network-shared-folder-windows-11)
- **3**: [https://woshub.com/cached-domain-logon-credentials-windows/](https://woshub.com/cached-domain-logon-credentials-windows/)
- **4**: [https://knowledge.complexsecurity.io/cryptography/dpapi](https://knowledge.complexsecurity.io/cryptography/dpapi)
- **5**: [https://www.coresecurity.com/core-labs/articles/reading-dpapi-encrypted-keys-mimikatz](https://www.coresecurity.com/core-labs/articles/reading-dpapi-encrypted-keys-mimikatz)
- **6**: [https://blog.gitguardian.com/top-10-file-extensions/](https://blog.gitguardian.com/top-10-file-extensions/)
- **7**: [https://news.softpedia.com/news/russian-apts-prefer-windows-office-internet-explorer-exploits-507051.shtml](https://news.softpedia.com/news/russian-apts-prefer-windows-office-internet-explorer-exploits-507051.shtml)
- **8**: [https://spectralops.io/blog/where-your-code-secrets-hide-filetypes](https://spectralops.io/blog/where-your-code-secrets-hide-filetypes)
- **9**: [https://www.converter365.com/blog/most-common-file-extensions-for-windows/](https://www.converter365.com/blog/most-common-file-extensions-for-windows/)
- **10**: [https://unit42.paloaltonetworks.com/behind-the-scenes-with-oilrig/](https://unit42.paloaltonetworks.com/behind-the-scenes-with-oilrig/)

## Description
Credential dumping is the process of extracting sensitive information, such
as passwords, normally in the form of a hash or a clear text content, as well
as any other secrets stored on the compromised host ref [1], [2].         

On Windows, the user's passwords and secrets can be stored in multiple
possible locations, accessible with Windows File Explorer.  

For example:

### Security Accounts Manager (SAM) database location

Location of the SAM database, contains the local users of the host as well
as the local groups: 

`%SystemRoot%/system32/config/SAM`

### Windows Security configuration file

Security config file contains LSA Secrets, for example DPAPI machine key,
account cleartext passwords for Windows services or scheduled tasks that
are configured on the host. Data Protection API (DPAPI) performs symmetric
encryption of asymmetric private keys and it's used by the operation system
to securely store passwords, encryption keys or any other type of sensitive
data ref [3], [4] and [5].        

`%SystemRoot%/system32/config/SECURITY`

### AppData local user folder

AppData in the local user folder contains cleartext passwords,
web browsers cookies and other cached browser data:  

`%SYSTEMDRIVE%\Users\<USERNAME>\AppData\Local\Microsoft\Vault\<GUID>`

### Other possible Windows explorer locations for browsing

Some other paths in Windows Explorer may contain password manager details,
for example KeePass Password Database or similar.  

Examples for paths in Windows Explorer (local locations or network shares):

- `C:\Users\Public\TempWorkingFiles\PGM\Documents\Keepass\`
- `C:\Users\vernada\AppData\Local\Microsoft\AppV\Client\Integration\{identifier_string}\Root`
- `C:\ProgramData\AppV\{identifier_string}\Root\KeePass.exe`
- `C:\Users\USERNAME\Downloads\EBSI credentials\`
- `E:\KeePass-db\`  

### Automated scripts

The threat actors are using automated scripts that can search for specific
file extentions in Windows Explorer that usually contain sensitive data as 
user and system credentials.  

#### Batch script to search for files by a name

Example:

```
@echo off
set /p search_term=Enter search term: 
for /f "delims=" %%a in ('dir /b /s *%search_term%*') do echo %%a
```

#### PowerShell script to search for files in Windows by content

Example:

```
$search_term = Read-Host "Enter search term"
Get-ChildItem -Path C:\ -Recurse | Select-String -Pattern $search_term
```

#### Known extentions for files (possible to be discovered via Windows Explorer)

Browsing through Windows Explorer, threat actors are usually looking for
file extentions of files which may contain user's credentials ref [6].  

Example for file extensions that may contain credentials:  

- Compressed (archive) files: .zip, .tar, .gz, .tgz, .rar, and others
- Java source files: .java
- Text files: .txt
- PDF documents: .pdf 
- Office file documents: .doc, .docx, .rtf, .xlsx, .pptx, .pps, .ppsm, .ppsx, .ppt
- Backup files: .bak, .old and others
- Archive files: .7z, .zip , .rar
- Database files: .kd , kdbx, mdb
- Configuration files: .config, .xml, .xsml, .xsl, .xsd, .xps, .sys
- Execution files: .exe, .cmd, .ps1
- Libraries: .dll
- Shell configuration files: .bashrc, .zshrc, .cshrc
- User AWS Folder .aws/credentials
- Other possible files that may contain credentials: csv, tmp, .ssh, .wxs

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor is using an already compromised Windows endpoint.

Domains: Enterprise, Public Cloud, Private Cloud
Targets: Desktop, Laptop, End-user, Control Server, Remote access, System admin, Public-Facing Servers, Web Application Servers, Customer, Other
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft; Impairement | - |
| Leverage | Tampering; Infrastructure Compromise; Information Disclosure | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT28](https://attack.mitre.org/groups/G0007) | `att&ck::G0007` | ('att&ck',) | [APT28](https://attack.mitre.org/groups/G0007) is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165.(Citation: NSA/FBI Drovorub August 2020)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021) This group has been active since at least 2004.(Citation: DOJ GRU Indictment Jul 2018)(Citation: Ars Technica GRU indictment Jul 2018)(Citation: Crowdstrike DNC June 2016)(Citation: FireEye APT28)(Citation: SecureWorks TG-4127)(Citation: FireEye APT28 January 2017)(Citation: GRIZZLY STEPPE JAR)(Citation: Sofacy DealersChoice)(Citation: Palo Alto Sofacy 06-2018)(Citation: Symantec APT28 Oct 2018)(Citation: ESET Zebrocy May 2019)  [APT28](https://attack.mitre.org/groups/G0007) reportedly compromised the Hillary Clinton campaign, the Democratic National Committee, and the Democratic Congressional Campaign Committee in 2016 in an attempt to interfere with the U.S. presidential election.(Citation: Crowdstrike DNC June 2016) In 2018, the US indicted five GRU Unit 26165 officers associated with [APT28](https://attack.mitre.org/groups/G0007) for cyber operations (including close-access operations) conducted between 2014 and 2018 against the World Anti-Doping Agency (WADA), the US Anti-Doping Agency, a US nuclear facility, the Organization for the Prohibition of Chemical Weapons (OPCW), the Spiez Swiss Chemicals Laboratory, and other organizations.(Citation: US District Court Indictment GRU Oct 2018) Some of these were conducted with the assistance of GRU Unit 74455, which is also referred to as [Sandworm Team](https://attack.mitre.org/groups/G0034). |
| APT28 | `misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754` | ('misp',) | The Sofacy Group (also known as APT28, Pawn Storm, Fancy Bear and Sednit) is a cyber espionage group believed to have ties to the Russian government. Likely operating since 2007, the group is known to target government, military, and security organizations. It has been characterized as an advanced persistent threat. |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |
| [[Enterprise] OilRig](https://attack.mitre.org/groups/G0049) | `att&ck::G0049` | ('att&ck',) | [OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of sectors, including financial, government, energy, chemical, and telecommunications. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. The group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests.(Citation: FireEye APT34 Dec 2017)(Citation: Palo Alto OilRig April 2017)(Citation: ClearSky OilRig Jan 2017)(Citation: Palo Alto OilRig May 2016)(Citation: Palo Alto OilRig Oct 2016)(Citation: Unit42 OilRig Playbook 2023)(Citation: Unit 42 QUADAGENT July 2018) |
| OilRig | `misp::42be2a84-5a5c-4c6d-9864-3f09d75bb0ba` | ('misp',) | OilRig is an Iranian threat group operating primarily in the Middle East by targeting organizations in this region that are in a variety of different industries; however, this group has occasionally targeted organizations outside of the Middle East as well. It also appears OilRig carries out supply chain attacks, where the threat group leverages the trust relationship between organizations to attack their primary targets.   OilRig is an active and organized threat group, which is evident based on their systematic targeting of specific organizations that appear to be carefully chosen for strategic purposes. Attacks attributed to this group primarily rely on social engineering to exploit the human rather than software vulnerabilities; however, on occasion this group has used recently patched vulnerabilities in the delivery phase of their attacks. The lack of software vulnerability exploitation does not necessarily suggest a lack of sophistication, as OilRig has shown maturity in other aspects of their operations. Such maturities involve:  -Organized evasion testing used the during development of their tools. -Use of custom DNS Tunneling protocols for command and control (C2) and data exfiltration. -Custom web-shells and backdoors used to persistently access servers.  OilRig relies on stolen account credentials for lateral movement. After OilRig gains access to a system, they use credential dumping tools, such as Mimikatz, to steal credentials to accounts logged into the compromised system. The group uses these credentials to access and to move laterally to other systems on the network. After obtaining credentials from a system, operators in this group prefer to use tools other than their backdoors to access the compromised systems, such as remote desktop and putty. OilRig also uses phishing sites to harvest credentials to individuals at targeted organizations to gain access to internet accessible resources, such as Outlook Web Access.    Since at least 2014, an Iranian threat group tracked by FireEye as APT34 has conducted reconnaissance aligned with the strategic interests of Iran. The group conducts operations primarily in the Middle East, targeting financial, government, energy, chemical, telecommunications and other industries. Repeated targeting of Middle Eastern financial, energy and government organizations leads FireEye to assess that those sectors are a primary concern of APT34. The use of infrastructure tied to Iranian operations, timing and alignment with the national interests of Iran also lead FireEye to assess that APT34 acts on behalf of the Iranian government. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |
| `T1552.001` | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001) | Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.  It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003).(Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.(Citation: SRD GPP)  In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files.(Citation: Unit 42 Hildegard Malware) They may also be found as parameters to deployment commands in container logs.(Citation: Unit 42 Unsecured Docker Daemons) In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.(Citation: Specter Ops - Cloud Credential Storage) |
| `T1005` | [Data from Local System](https://attack.mitre.org/techniques/T1005) | Adversaries may search local system sources, such as file systems, configuration files, local databases, or virtual machine files, to find files of interest and sensitive data prior to Exfiltration.  Adversaries may do this using a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), such as [cmd](https://attack.mitre.org/software/S0106) as well as a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008), which have functionality to interact with the file system to gather information.(Citation: show_run_config_cmd_cisco) Adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on the local system. |
| `T1552` | [Unsecured Credentials](https://attack.mitre.org/techniques/T1552) | Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)),  or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).(Citation: Brining MimiKatz to Unix) |
