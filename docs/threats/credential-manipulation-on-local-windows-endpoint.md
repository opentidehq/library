# Credential manipulation on local Windows endpoint

## Metadata

- **UUID**: `ec8201d4-c135-406b-a3b5-4a070e80a2ee`
- **Schema**: `threat::1.0`
- **Version**: `4`
- **Created**: `2023-02-02`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)
- **2**: [https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
- **3**: [https://www.pwndefend.com/2021/08/07/dumping-credentails-with-mimikatz-and-passing-the-hash-pth/](https://www.pwndefend.com/2021/08/07/dumping-credentails-with-mimikatz-and-passing-the-hash-pth/)
- **4**: [https://www.microsoft.com/en-us/security/blog/2019/05/09/detecting-credential-theft-through-memory-access-modelling-with-microsoft-defender-atp/](https://www.microsoft.com/en-us/security/blog/2019/05/09/detecting-credential-theft-through-memory-access-modelling-with-microsoft-defender-atp/)
- **5**: [https://www.microsoft.com/en-us/security/blog/2018/09/27/out-of-sight-but-not-invisible-defeating-fileless-malware-with-behavior-monitoring-amsi-and-next-gen-av/](https://www.microsoft.com/en-us/security/blog/2018/09/27/out-of-sight-but-not-invisible-defeating-fileless-malware-with-behavior-monitoring-amsi-and-next-gen-av/)
- **6**: [https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/](https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/)

## Description
Credential manipulation on a local Windows endpoint refers to an act of
modifying, altering, or stealing sensitive information such as usernames,
passwords, and other authentication data.   

An example of credential manipulation could be the usage of a tool, for
example like Mimikatz to extract login credentials from memory or to
manipulate and modify existing credentials stored on the local system.
The threat actor could use these manipulated credentials to gain
unauthorized access to other systems or network resources.   

The threat actors abuse and some legitimate administrator tools, such as
the Microsoft Sysinternals tool: ProcDump or Task Manager to dump lsass.exe
process memory and to collect credentials. This approach is common and
known as "living-off-the-land", which means usage of legit native Windows
tools in order to avoid possible detection.   

Threat actors can gather, modify or delete credentials on the local Windows
system also by using Windows Explorer manually or with scrips to access
local files that may store user's or system credentials. For example
Keepass or other local databases which contain passwords.   

Examples:   

Threat actors are using Mimikatz LSADUMP Module to collect SAM registry
hashes.   

lsadump::sam   

Or to extract credentials from LSASS Dump files. 
Mimikatz module lsass.exe dumps credentials in a more stealthy mode.
The lsass.exe process manages many user credential secrets and can be
associated with credential theft behavior.   

sekurlsa::minidump lsass.dmp
log lsass.txt
sekurlsa::logonPasswords   

For extracting of Domain Controller cached credentials is used LSADUMP module:
lsadump::cache   

Locally, the threat actors can run sekurlsa Mimikatz module to obtain logon
credentials:   

sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords   

Built-in Windows tools such as comsvcs.dll can also be used:   

rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full   

There are variety of different tools that the threat actors use for
memory dump, for example:   

- Taskmgr.exe
- ProcDump
- ProcessExplorer.exe
- Process Hacker
- SQLDumper
- PowerSploit – Out-MiniDump
- VM Memory Dump Files
- Hibernation Files

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor is using already compromised Windows endpoint.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: Desktop, Laptop, End-user, Workstations, Control Server, System admin, Public-Facing Servers, Web Application Servers
Platforms: Windows, Active Directory**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Nuisance | Small and mostly inconsequential to day to day operations, but noticed. |
| Leverage | Tampering | Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Sandworm Team](https://attack.mitre.org/groups/G0034) | `att&ck::G0034` | ('att&ck',) | [Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)  In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018) |
| GreyEnergy | `misp::d52ca4c4-d214-11e8-8d29-c3e7cb78acce` | ('misp',) | ESET research reveals a successor to the infamous BlackEnergy APT group targeting critical infrastructure, quite possibly in preparation for damaging attacks |
| [[Enterprise] MuddyWater](https://attack.mitre.org/groups/G0069) | `att&ck::G0069` | ('att&ck',) | [MuddyWater](https://attack.mitre.org/groups/G0069) is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).(Citation: CYBERCOM Iranian Intel Cyber January 2022) Since at least 2017, [MuddyWater](https://attack.mitre.org/groups/G0069) has targeted a range of government and private organizations across sectors, including telecommunications, local government, defense, and oil and natural gas organizations, in the Middle East, Asia, Africa, Europe, and North America.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022) |
| MuddyWater | `misp::a29af069-03c3-4534-b78b-7d1a77ea085b` | ('misp',) | The MuddyWater attacks are primarily against Middle Eastern nations. However, we have also observed attacks against surrounding nations and beyond, including targets in India and the USA. MuddyWater attacks are characterized by the use of a slowly evolving PowerShell-based first stage backdoor we call “POWERSTATS”. Despite broad scrutiny and reports on MuddyWater attacks, the activity continues with only incremental changes to the tools and techniques. |
| [[Enterprise] Mustang Panda](https://attack.mitre.org/groups/G0129) | `att&ck::G0129` | ('att&ck',) | [Mustang Panda](https://attack.mitre.org/groups/G0129) is a China-based cyber espionage threat actor that was first observed in 2017 but may have been conducting operations since at least 2014. [Mustang Panda](https://attack.mitre.org/groups/G0129) has targeted government entities, nonprofits, religious, and other non-governmental organizations in the U.S., Europe, Mongolia, Myanmar, Pakistan, and Vietnam, among others.(Citation: Crowdstrike MUSTANG PANDA June 2018)(Citation: Anomali MUSTANG PANDA October 2019)(Citation: Secureworks BRONZE PRESIDENT December 2019) |
| RedDelta | `misp::fceed509-938e-4f9e-acd4-76e6c28dc6f1` | ('misp',) | Likely Chinese state-sponsored threat activity group RedDelta targeting organizations within Europe and Southeast Asia using a customized variant of the PlugX backdoor. Since at least 2019, RedDelta has been consistently active within Southeast Asia, particularly in Myanmar and Vietnam, but has also routinely adapted its targeting in response to global geopolitical events. This is historically evident through the group’s targeting of the Vatican and other Catholic organizations in the lead-up to 2021 talks between Chinese Communist Party (CCP) and Vatican officials, as well as throughout 2022 through the group’s shift towards increased targeting of European government and diplomatic entities following Russia’s invasion of Ukraine.  During the 3-month period from September through November 2022, RedDelta has regularly used an infection chain employing malicious shortcut (LNK) files, which trigger a dynamic-link library (DLL) search-order-hijacking execution chain to load consistently updated PlugX versions. Throughout this period, the group repeatedly employed decoy documents specific to government and migration policy within Europe. Of note, we identified a European government department focused on trade communicating with RedDelta command-and-control (C2) infrastructure in early August 2022. This activity commenced on the same day that a RedDelta PlugX sample using this C2 infrastructure and featuring an EU trade-themed decoy document surfaced on public malware repositories. We also identified additional probable victim entities within Myanmar and Vietnam regularly communicating with RedDelta C2 infrastructure.  RedDelta closely overlaps with public industry reporting under the aliases BRONZE PRESIDENT, Mustang Panda, TA416, Red Lich, and HoneyMyte. |
| [[Enterprise] Fox Kitten](https://attack.mitre.org/groups/G0117) | `att&ck::G0117` | ('att&ck',) | [Fox Kitten](https://attack.mitre.org/groups/G0117) is threat actor with a suspected nexus to the Iranian government that has been active since at least 2017 against entities in the Middle East, North Africa, Europe, Australia, and North America. [Fox Kitten](https://attack.mitre.org/groups/G0117) has targeted multiple industrial verticals including oil and gas, technology, government, defense, healthcare, manufacturing, and engineering.(Citation: ClearkSky Fox Kitten February 2020)(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: Dragos PARISITE )(Citation: ClearSky Pay2Kitten December 2020) |
| Fox Kitten | `misp::bfb0bc20-5bdf-47ff-b07f-dbd9a3cb9772` | ('misp',) | PIONEER KITTEN is an Iran-based adversary that has been active since at least 2017 and has a suspected nexus to the Iranian government. This adversary appears to be primarily focused on gaining and maintaining access to entities possessing sensitive information of likely intelligence interest to the Iranian government. According to DRAGOS, they also targeted ICS-related entities using known VPN vulnerabilities. They are widely known to use open source penetration testing tools for reconnaissance and to establish encrypted communications. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1098` | [Account Manipulation](https://attack.mitre.org/techniques/T1098) | Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.(Citation: FireEye SMOKEDHAM June 2021) These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.   In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078). |
| `T1098.001` | [Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) | Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.  For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID.(Citation: Microsoft SolarWinds Customer Guidance)(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) These credentials include both x509 keys and passwords.(Citation: Microsoft SolarWinds Customer Guidance) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules.(Citation: Demystifying Azure AD Service Principals)  In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys using either the <code>CreateKeyPair</code> or <code>ImportKeyPair</code> API in AWS or the <code>gcloud compute os-login ssh-keys add</code> command in GCP.(Citation: GCP SSH Key Add) This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts.(Citation: Expel IO Evil in AWS)(Citation: Expel Behind the Scenes)  Adversaries may also use the <code>CreateAccessKey</code> API in AWS or the <code>gcloud iam service-accounts keys create</code> command in GCP to add access keys to an account. Alternatively, they may use the <code>CreateLoginProfile</code> API in AWS to add a password that can be used to log into the AWS Management Console for [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538).(Citation: Permiso Scattered Spider 2023)(Citation: Lacework AI Resource Hijacking 2024) If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)).(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Sysdig ScarletEel 2.0) For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator.(Citation: SpecterOps Azure Privilege Escalation)   In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to [Forge Web Credentials](https://attack.mitre.org/techniques/T1606) tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated. (Citation: Crowdstrike AWS User Federation Persistence)  In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account.(Citation: Mandiant APT42 Operations 2024) As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.(Citation: Microsoft Entra ID App Passwords) |
| `T1552.001` | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001) | Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.  It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003).(Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.(Citation: SRD GPP)  In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files.(Citation: Unit 42 Hildegard Malware) They may also be found as parameters to deployment commands in container logs.(Citation: Unit 42 Unsecured Docker Daemons) In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.(Citation: Specter Ops - Cloud Credential Storage) |
| `T1003.001` | [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001) | Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).  As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.  For example, on the target host use procdump:  * <code>procdump -ma lsass.exe lsass_dump</code>  Locally, mimikatz can be run using:  * <code>sekurlsa::Minidump lsassdump.dmp</code> * <code>sekurlsa::logonPasswords</code>  Built-in Windows tools such as `comsvcs.dll` can also be used:  * <code>rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID  lsass.dmp full</code>(Citation: Volexity Exchange Marauder March 2021)(Citation: Symantec Attacks Against Government Sector)  Similar to [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012), the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`).(Citation: Deep Instinct LSASS)  Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)  The following SSPs can be used to access credentials:  * Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package. * Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection) * Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later. * CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection) |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |

## Chaining
```mermaid
flowchart LR
ec8201d4_c135_406b_a3b5_4a070e80a2ee["Credential manipulation on local Windows endpoint"]
5ea50181_1124_49aa_9d2c_c74103e86fd5["Pass-the-hash on SMB network shares"]
03cc9593_e7cf_484b_ae9c_684bf6f7199f["Pass the ticket using Kerberos ticket"]
479a8b31_5f7e_4fd6_94ca_a5556315e1b8["Pass the hash using impersonation within an existing process"]
4472e2b0_3dca_4d84_aab0_626fcba04fce["Pass the hash attack to elevate privileges"]
7351e2ca_e198_427c_9cfa_202df36f6e2a["Mimikatz execution on compromised endpoint"]
06523ed4_7881_4466_9ac5_f8417e972d13["Using a Windows command prompt for credential manipulation"]
e3d7cb59_7aca_4c3d_b488_48c785930b6d["PowerShell usage for credential manipulation"]
a566e405_e9db_475f_8447_7875fa127716["Script execution on Windows for credential manipulation"]
2d0beed6_6520_4114_be1f_24067628e93c["Manipulation of credentials stored in LSASS"]
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|sequence::succeeds| 5ea50181_1124_49aa_9d2c_c74103e86fd5
5ea50181_1124_49aa_9d2c_c74103e86fd5 -->|sequence::succeeds| 03cc9593_e7cf_484b_ae9c_684bf6f7199f
03cc9593_e7cf_484b_ae9c_684bf6f7199f -->|sequence::succeeds| 479a8b31_5f7e_4fd6_94ca_a5556315e1b8
479a8b31_5f7e_4fd6_94ca_a5556315e1b8 -->|sequence::succeeds| 4472e2b0_3dca_4d84_aab0_626fcba04fce
4472e2b0_3dca_4d84_aab0_626fcba04fce -->|atomicity::implements| 7351e2ca_e198_427c_9cfa_202df36f6e2a
7351e2ca_e198_427c_9cfa_202df36f6e2a -->|atomicity::implements| 06523ed4_7881_4466_9ac5_f8417e972d13
06523ed4_7881_4466_9ac5_f8417e972d13 -->|atomicity::implements| e3d7cb59_7aca_4c3d_b488_48c785930b6d
e3d7cb59_7aca_4c3d_b488_48c785930b6d -->|atomicity::implements| a566e405_e9db_475f_8447_7875fa127716
a566e405_e9db_475f_8447_7875fa127716 -->|sequence::preceeds| 2d0beed6_6520_4114_be1f_24067628e93c
```
### Chaining details
#### succeeds -> Pass-the-hash on SMB network shares (`sequence::succeeds`)
In a **Pass-the-Hash attack (PtH)**, Attackers may use offensive tools to load 
the NTLM hash and try to connect to SMB network shares that are...

- **Target UUID**: `5ea50181-1124-49aa-9d2c-c74103e86fd5`
#### succeeds -> Pass the ticket using Kerberos ticket (`sequence::succeeds`)
Pass-the-Ticket using Kerberos tickets is an advanced method wherein threat 
actors illicitly extract and exploit Kerberos tickets to gain unauthorized...

- **Target UUID**: `03cc9593-e7cf-484b-ae9c-684bf6f7199f`
#### succeeds -> Pass the hash using impersonation within an existing process (`sequence::succeeds`)
Adversaries may use a particular flavor of pass the hash - to leverage 
an acquired handle (hash) on NT AUTHORITY\SYSTEM access token to spawn a 
new ...

- **Target UUID**: `479a8b31-5f7e-4fd6-94ca-a5556315e1b8`
#### succeeds -> Pass the hash attack to elevate privileges (`sequence::succeeds`)
Elevating privileges on Windows to System allows a threat actor (or 
sysadmin) to do things that are not possible without SYSTEM/root 
privileges.

- **Target UUID**: `4472e2b0-3dca-4d84-aab0-626fcba04fce`
#### implements -> Mimikatz execution on compromised endpoint (`atomicity::implements`)
Mimikatz is a very versatile tool that comes with a lot of 
options and capabilities. Detection of known Atomic IOCs of 
the mimikatz tool itself or...

- **Target UUID**: `7351e2ca-e198-427c-9cfa-202df36f6e2a`
#### implements -> Using a Windows command prompt for credential manipulation (`atomicity::implements`)
Threat actors may use Windows commad prompt commands to search for, access
in order to manipulate (create, modify, delete, read) user's credentials...

- **Target UUID**: `06523ed4-7881-4466-9ac5-f8417e972d13`
#### implements -> PowerShell usage for credential manipulation (`atomicity::implements`)
Threat actors are using different methods to manipulate user's credentials.
One example of credential manipulation is by using PowerShell commands or
...

- **Target UUID**: `e3d7cb59-7aca-4c3d-b488-48c785930b6d`
#### implements -> Script execution on Windows for credential manipulation (`atomicity::implements`)
One example of script execution for credential manipulation is the use of a
Python or other type of script to access and read/change a user's credential...

- **Target UUID**: `a566e405-e9db-475f-8447-7875fa127716`
#### preceeds -> Manipulation of credentials stored in LSASS (`sequence::preceeds`)
Credentials can be stored in the Local Security Authority Subsystem
Service (LSASS) process in memory for use by the account. LSASS stores
credentials...

- **Target UUID**: `2d0beed6-6520-4114-be1f-24067628e93c`
