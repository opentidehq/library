# Abuse of Getsystem command for privilege escalation

## Metadata

- **UUID**: `49625e57-94e0-4185-8466-ac68fe15b7e1`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2025-02-03`
- **Modified**: `2025-02-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)
- **2**: [https://redcanary.com/threat-detection-report/threats/cobalt-strike/](https://redcanary.com/threat-detection-report/threats/cobalt-strike/)
- **3**: [https://www.offsec.com/metasploit-unleashed/privilege-escalation/](https://www.offsec.com/metasploit-unleashed/privilege-escalation/)

## Description
Use of Getsystem command to elevate from a local administrator to the SYSTEM user.
There are different tools to do this, most popular are Cobalt Strike beacons and 
Metasploit Meterpreter payload.

Both tools first attempt to use “named pipe impersonation” to achieve SYSTEM privileges.
This involves creating a Windows Service to execute as NT AUTHORITY\SYSTEM and feeding
data to it through a named pipe that is randomly created by the malicious payload.

The getsystem command has three techniques. The first two rely on named pipe impersonation.
The last one relies on token duplication.

## Technique 1.

It creates a named pipe from Meterpreter. It also creates and runs a service that runs
cmd.exe /c echo “some data” >\\.\pipe\[random pipe here]. When the spawned cmd.exe connects
to Meterpreter’s named pipe, Meterpreter has the opportunity to impersonate that security 
context. Impersonation of clients is a named pipes feature. 
The context of the service is SYSTEM, so when you impersonate it, you become SYSTEM.

## Technique 2.

It is like technique 1. It creates a named pipe and impersonates the security context of
the first client to connect to it. To create a client with the SYSTEM user context,
this technique drops a DLL to disk(and schedules rundll32.exe as a service to run the
DLL as SYSTEM. The DLL connects to the named pipe.

## Technique 3.

It is a little different. This technique assumes you have SeDebugPrivileges—something getprivs
can help with. It loops through all open services to find one that is running as SYSTEM and
that you have permissions to inject into. It uses reflective DLL injection to run its elevator.dll
in the memory space of the service it finds. This technique also passes the current thread id 
(from Meterpreter) to elevator.dll. When run, elevator.dll gets the SYSTEM token, opens the primary 
thread in Meterpreter, and tries to apply the SYSTEM token to it.

This technique’s implementation limits itself to x86 environments only. On the bright side, 
it does not require spawning a new process and it takes place entirely in memory.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversary must have administrative privileges on Windows systems within 
the enterprise network.

Domains: Enterprise
Targets: Laptop, Workstations
Platforms: Active Directory, PowerShell, Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Business disruption; Reputational Damages; Operating costs | - |
| Leverage | Modify configuration; Modify data; Tampering; New Accounts | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Aquatic Panda](https://attack.mitre.org/groups/G0143) | `att&ck::G0143` | ('att&ck',) | [Aquatic Panda](https://attack.mitre.org/groups/G0143) is a suspected China-based threat group with a dual mission of intelligence collection and industrial espionage. Active since at least May 2020, [Aquatic Panda](https://attack.mitre.org/groups/G0143) has primarily targeted entities in the telecommunications, technology, and government sectors.(Citation: CrowdStrike AQUATIC PANDA December 2021) |
| [[Enterprise] Cobalt Group](https://attack.mitre.org/groups/G0080) | `att&ck::G0080` | ('att&ck',) | [Cobalt Group](https://attack.mitre.org/groups/G0080) is a financially motivated threat group that has primarily targeted financial institutions since at least 2016. The group has conducted intrusions to steal money via targeting ATM systems, card processing, payment systems and SWIFT systems. [Cobalt Group](https://attack.mitre.org/groups/G0080) has mainly targeted banks in Eastern Europe, Central Asia, and Southeast Asia. One of the alleged leaders was arrested in Spain in early 2018, but the group still appears to be active. The group has been known to target organizations in order to use their access to then compromise additional victims.(Citation: Talos Cobalt Group July 2018)(Citation: PTSecurity Cobalt Group Aug 2017)(Citation: PTSecurity Cobalt Dec 2016)(Citation: Group IB Cobalt Aug 2017)(Citation: Proofpoint Cobalt June 2017)(Citation: RiskIQ Cobalt Nov 2017)(Citation: RiskIQ Cobalt Jan 2018) Reporting indicates there may be links between [Cobalt Group](https://attack.mitre.org/groups/G0080) and both the malware [Carbanak](https://attack.mitre.org/software/S0030) and the group [Carbanak](https://attack.mitre.org/groups/G0008).(Citation: Europol Cobalt Mar 2018) |
| [[Enterprise] Cinnamon Tempest](https://attack.mitre.org/groups/G1021) | `att&ck::G1021` | ('att&ck',) | [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) is a China-based threat group that has been active since at least 2021 deploying multiple strains of ransomware based on the leaked [Babuk](https://attack.mitre.org/software/S0638) source code. [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) does not operate their ransomware on an affiliate model or purchase access but appears to act independently in all stages of the attack lifecycle. Based on victimology, the short lifespan of each ransomware variant, and use of malware attributed to government-sponsored threat groups, [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) may be motivated by intellectual property theft or cyberespionage rather than financial gain.(Citation: Microsoft Ransomware as a Service)(Citation: Microsoft Threat Actor Naming July 2023)(Citation: Trend Micro Cheerscrypt May 2022)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022) |
| [[Enterprise] LuminousMoth](https://attack.mitre.org/groups/G1014) | `att&ck::G1014` | ('att&ck',) | [LuminousMoth](https://attack.mitre.org/groups/G1014) is a Chinese-speaking cyber espionage group that has been active since at least October 2020. [LuminousMoth](https://attack.mitre.org/groups/G1014) has targeted high-profile organizations, including government entities, in Myanmar, the Philippines, Thailand, and other parts of Southeast Asia. Some security researchers have concluded there is a connection between [LuminousMoth](https://attack.mitre.org/groups/G1014) and [Mustang Panda](https://attack.mitre.org/groups/G0129) based on similar targeting and TTPs, as well as network infrastructure overlaps.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021) |
| MUSTANG PANDA | `misp::78bf726c-a9e6-11e8-9e43-77249a2f7339` | ('misp',) | This threat actor targets nongovernmental organizations using Mongolian-themed lures for espionage purposes. In April 2017, CrowdStrike Falcon Intelligence observed a previously unattributed actor group with a Chinese nexus targeting a U.S.-based think tank. Further analysis revealed a wider campaign with unique tactics, techniques, and procedures (TTPs). This adversary targets non-governmental organizations (NGOs) in general, but uses Mongolian language decoys and themes, suggesting this actor has a specific focus on gathering intelligence on Mongolia. These campaigns involve the use of shared malware like Poison Ivy or PlugX. Recently, Falcon Intelligence observed new activity from MUSTANG PANDA, using a unique infection chain to target likely Mongolia-based victims. This newly observed activity uses a series of redirections and fileless, malicious implementations of legitimate tools to gain access to the targeted systems. Additionally, MUSTANG PANDA actors reused previously-observed legitimate domains to host files. |
| APT32 | `misp::aa29ae56-e54b-47a2-ad16-d3ab0242d5d7` | ('misp',) | Cyber espionage actors, now designated by FireEye as APT32 (OceanLotus Group), are carrying out intrusions into private sector companies across multiple industries and have also targeted foreign governments, dissidents, and journalists. FireEye assesses that APT32 leverages a unique suite of fully-featured malware, in conjunction with commercially-available tools, to conduct targeted operations that are aligned with Vietnamese state interests. |
| ToddyCat | `misp::091a0b69-74de-44b6-bb12-16b7a8fd078b` | ('misp',) | ToddyCat is responsible for multiple sets of attacks detected since December 2020 against high-profile entities in Europe and Asia. There is still little information about this actor, but its main distinctive signs are two formerly unknown tools that Kaspersky call ‘Samurai backdoor’ and ‘Ninja Trojan’. |
| APT19 | `misp::066d25c1-71bd-4bd4-8ca7-edbba00063f4` | ('misp',) | Adversary group targeting financial, technology, non-profit organisations. |
| TA505 | `misp::03c80674-35f8-4fe0-be2b-226ed0fcd69f` | ('misp',) | TA505, the name given by Proofpoint, has been in the cybercrime business for at least four years. This is the group behind the infamous Dridex banking trojan and Locky ransomware, delivered through malicious email campaigns via Necurs botnet. Other malware associated with TA505 include Philadelphia and GlobeImposter ransomware families. |
| CopyKittens | `misp::8cca9a1d-66e4-4bc4-ad49-95f759f4c1ae` | ('misp',) | - |
| DarkHydrus | `misp::ce2c2dfd-2445-4fbc-a747-9e7092e383f9` | ('misp',) | In July 2018, Unit 42 analyzed a targeted attack using a novel file type against at least one government agency in the Middle East. It was carried out by a previously unpublished threat group we track as DarkHydrus. Based on our telemetry, we were able to uncover additional artifacts leading us to believe this adversary group has been in operation with their current playbook since early 2016. This attack diverged from previous attacks we observed from this group as it involved spear-phishing emails sent to targeted organizations with password protected RAR archive attachments that contained malicious Excel Web Query files (.iqy). |
| Mustard Tempest | `misp::3ce9610b-2435-4c41-80d1-3f95a5ff2984` | ('misp',) | Mustard Tempest is a threat actor that primarily uses malvertising as their main technique to gain access to and profile networks. They deploy FakeUpdates, disguised as browser updates or software packages, to lure targets into downloading a ZIP file containing a JavaScript file. Once executed, the JavaScript framework acts as a loader for other malware campaigns, often Cobalt Strike payloads. Mustard Tempest has been associated with the cybercrime syndicate Mustard Tempest, also known as EvilCorp, and has been involved in ransomware attacks using payloads such as WastedLocker, PhoenixLocker, and Macaw. |
| APT41 | `misp::9c124874-042d-48cd-b72b-ccdc51ecbbd6` | ('misp',) | APT41 is a prolific cyber threat group that carries out Chinese state-sponsored espionage activity in addition to financially motivated activity potentially outside of state control. |
| APT10 | `misp::56b37b05-72e7-4a89-ba8a-61ce45269a8c` | ('misp',) | menuPass is a threat group that has been active since at least 2006. Individual members of menuPass are known to have acted in association with the Chinese Ministry of State Security's (MSS) Tianjin State Security Bureau and worked for the Huaying Haitai Science and Technology Development Company. |
| FIN7 | `misp::00220228-a5a4-4032-a30d-826bb55aa3fb` | ('misp',) | Groups targeting financial organizations or people with significant financial assets. |
| Sandworm | `misp::f512de42-f76b-40d2-9923-59e7dbdfec35` | ('misp',) | This threat actor targets industrial control systems, using a tool called Black Energy, associated with electricity and power generation for espionage, denial of service, and data destruction purposes. Some believe that the threat actor is linked to the 2015 compromise of the Ukrainian electrical grid and a distributed denial of service prior to the Russian invasion of Georgia. Believed to be responsible for the 2008 DDoS attacks in Georgia and the 2015 Ukraine power grid outage |
| APT40 | `misp::5b4b6980-3bc7-11e8-84d6-879aaac37dd9` | ('misp',) | Leviathan is an espionage actor targeting organizations and high-value targets in defense and government. Active since at least 2014, this actor has long-standing interest in maritime industries, naval defense contractors, and associated research institutions in the United States and Western Europe. |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |
| APT37 | `misp::50cd027f-df14-40b2-aa22-bf5de5061163` | ('misp',) | APT37 has likely been active since at least 2012 and focuses on targeting the public and private sectors primarily in South Korea. In 2017, APT37 expanded its targeting beyond the Korean peninsula to include Japan, Vietnam and the Middle East, and to a wider range of industry verticals, including chemicals, electronics, manufacturing, aerospace, automotive and healthcare entities |
| WIZARD SPIDER | `misp::bdf4fe4f-af8a-495f-a719-cf175cecda1f` | ('misp',) | Wizard Spider is reportedly associated with Grim Spider and Lunar Spider. The WIZARD SPIDER threat group is the Russia-based operator of the TrickBot banking malware. This group represents a growing criminal enterprise of which GRIM SPIDER appears to be a subset. The LUNAR SPIDER threat group is the Eastern European-based operator and developer of the commodity banking malware called BokBot (aka IcedID), which was first observed in April 2017. The BokBot malware provides LUNAR SPIDER affiliates with a variety of capabilities to enable credential theft and wire fraud, through the use of webinjects and a malware distribution function. GRIM SPIDER is a sophisticated eCrime group that has been operating the Ryuk ransomware since August 2018, targeting large organizations for a high-ransom return. This methodology, known as “big game hunting,” signals a shift in operations for WIZARD SPIDER, a criminal enterprise of which GRIM SPIDER appears to be a cell. The WIZARD SPIDER threat group, known as the Russia-based operator of the TrickBot banking malware, had focused primarily on wire fraud in the past. |
| INDRIK SPIDER | `misp::658314bc-3bb8-48d2-913a-c528607b75c8` | ('misp',) | INDRIK SPIDER is a sophisticated eCrime group that has been operating Dridex since June 2014. In 2015 and 2016, Dridex was one of the most prolific eCrime banking trojans on the market and, since 2014, those efforts are thought to have netted INDRIK SPIDER millions of dollars in criminal profits. Throughout its years of operation, Dridex has received multiple updates with new modules developed and new anti-analysis features added to the malware. In August 2017, a new ransomware variant identified as BitPaymer was reported to have ransomed the U.K.’s National Health Service (NHS), with a high ransom demand of 53 BTC (approximately $200,000 USD). The targeting of an organization rather than individuals, and the high ransom demands, made BitPaymer stand out from other contemporary ransomware at the time. Though the encryption and ransom functionality of BitPaymer was not technically sophisticated, the malware contained multiple anti-analysis features that overlapped with Dridex. Later technical analysis of BitPaymer indicated that it had been developed by INDRIK SPIDER, suggesting the group had expanded its criminal operation to include ransomware as a monetization strategy. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1134.002` | [Access Token Manipulation: Create Process with Token](https://attack.mitre.org/techniques/T1134/002) | Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as <code>CreateProcessWithTokenW</code> and <code>runas</code>.(Citation: Microsoft RunAs)  Creating processes with a token not associated with the current user may require the credentials of the target user, specific privileges to impersonate that user, or access to the token to be used. For example, the token could be duplicated via [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) or created via [Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) before being used to create a process.  While this technique is distinct from [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001), the techniques can be used in conjunction where a token is duplicated and then used to create a new process. |
