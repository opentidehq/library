# Pass the hash using impersonation within an existing process

## Metadata

- **UUID**: `479a8b31-5f7e-4fd6-94ca-a5556315e1b8`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2022-11-15`
- **Modified**: `2024-05-15`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://attack.mitre.org/techniques/T1550/002/](https://attack.mitre.org/techniques/T1550/002/)
- **2**: [https://adsecurity.org/?page_id=1821](https://adsecurity.org/?page_id=1821)
- **3**: [https://adsecurity.org/?p=2362](https://adsecurity.org/?p=2362)
- **4**: [https://www.sentinelone.com/cybersecurity-101/mimikatz/](https://www.sentinelone.com/cybersecurity-101/mimikatz/)
- **5**: [https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/pth](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/pth)
- **6**: [https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)
- **7**: [https://tools.thehacker.recipes/mimikatz/modules/sekurlsa](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa)
- **8**: [https://attack.mitre.org/software/S0154/](https://attack.mitre.org/software/S0154/)
- **9**: [https://www.tevora.com/threat-blog/about-windows-process-thread-tokens-and-pass-the-hash/](https://www.tevora.com/threat-blog/about-windows-process-thread-tokens-and-pass-the-hash/)
- **10**: [https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L975-L987](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L975-L987)
- **11**: [https://twitter.com/gentilkiwi/status/1592805645824425984?s=20&t=VyUJnGjfUYV4J21s-rS8ew](https://twitter.com/gentilkiwi/status/1592805645824425984?s=20&t=VyUJnGjfUYV4J21s-rS8ew)

## Description
Adversaries may use a particular flavor of pass the hash - to leverage 
an acquired handle (hash) on NT AUTHORITY\SYSTEM access token to spawn a 
new NT AUTHORITY\SYSTEM context process, impersonate the token for this
process into the attacker-desired existing thread, and then kill the 
spawned NT AUTHORITY\SYSTEM process again, making it a temp process used
to allow the threat actor to elevate privileges to NT AUTHORITY\SYSTEM.

This sets the technique apart from spawning a new process with the 
attacker-desired privileges that pass the hash without use of the 
/IMPERSONATE option leads to. 

Elevating privileges on Windows to System allows a threat actor (or 
sysadmin) to do things that are not possible without SYSTEM/root 
privileges.

Pass the hash is a method of authenticating as a user without having 
access to the user's cleartext password by stealing password hashes. This 
method bypasses standard authentication steps that require a cleartext 
password, moving directly into the portion of the authentication that uses 
the password hash. 

Mimikatz sekurlsa module with the /impersonate option implements this
particular approach as an option alongside other more known NTLM based
procedures.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires an already compromised endpoint.

Doing pass-the-hash on a Windows system requires specific privilege. 
It either requires elevated privileges (by previously running 
privilege:debug or by executing Mimikatz as the NT-AUTHORITY\SYSTEM 
account). This doesn't apply to pass-the-ticket which uses an official API.

Pth works on windows computers of every kind, however later versions 
natively have some level of defenses/mitigations built in.

Domains: Enterprise, Public Cloud
Targets: Auth token, Control Server, Workstations, End-user, Public-Facing Servers, Server Authentication, Laptop, Desktop
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Identity Theft; Impairement; Data Breach | - |
| Leverage | Elevation of privilege; Information Disclosure; Spoofing; Tampering; Repudiation | - |
| Viability | Very Likely | Highly probable - 80-95% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT28](https://attack.mitre.org/groups/G0007) | `att&ck::G0007` | ('att&ck',) | [APT28](https://attack.mitre.org/groups/G0007) is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165.(Citation: NSA/FBI Drovorub August 2020)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021) This group has been active since at least 2004.(Citation: DOJ GRU Indictment Jul 2018)(Citation: Ars Technica GRU indictment Jul 2018)(Citation: Crowdstrike DNC June 2016)(Citation: FireEye APT28)(Citation: SecureWorks TG-4127)(Citation: FireEye APT28 January 2017)(Citation: GRIZZLY STEPPE JAR)(Citation: Sofacy DealersChoice)(Citation: Palo Alto Sofacy 06-2018)(Citation: Symantec APT28 Oct 2018)(Citation: ESET Zebrocy May 2019)  [APT28](https://attack.mitre.org/groups/G0007) reportedly compromised the Hillary Clinton campaign, the Democratic National Committee, and the Democratic Congressional Campaign Committee in 2016 in an attempt to interfere with the U.S. presidential election.(Citation: Crowdstrike DNC June 2016) In 2018, the US indicted five GRU Unit 26165 officers associated with [APT28](https://attack.mitre.org/groups/G0007) for cyber operations (including close-access operations) conducted between 2014 and 2018 against the World Anti-Doping Agency (WADA), the US Anti-Doping Agency, a US nuclear facility, the Organization for the Prohibition of Chemical Weapons (OPCW), the Spiez Swiss Chemicals Laboratory, and other organizations.(Citation: US District Court Indictment GRU Oct 2018) Some of these were conducted with the assistance of GRU Unit 74455, which is also referred to as [Sandworm Team](https://attack.mitre.org/groups/G0034). |
| APT28 | `misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754` | ('misp',) | The Sofacy Group (also known as APT28, Pawn Storm, Fancy Bear and Sednit) is a cyber espionage group believed to have ties to the Russian government. Likely operating since 2007, the group is known to target government, military, and security organizations. It has been characterized as an advanced persistent threat. |
| [[Enterprise] APT1](https://attack.mitre.org/groups/G0006) | `att&ck::G0006` | ('att&ck',) | [APT1](https://attack.mitre.org/groups/G0006) is a Chinese threat group that has been attributed to the 2nd Bureau of the People’s Liberation Army (PLA) General Staff Department’s (GSD) 3rd Department, commonly known by its Military Unit Cover Designator (MUCD) as Unit 61398. (Citation: Mandiant APT1) |
| APT1 | `misp::1cb7e1cc-d695-42b1-92f4-fd0112a3c9be` | ('misp',) | PLA Unit 61398 (Chinese: 61398部队, Pinyin: 61398 bùduì) is the Military Unit Cover Designator (MUCD)[1] of a People's Liberation Army advanced persistent threat unit that has been alleged to be a source of Chinese computer hacking attacks |
| [[Enterprise] APT32](https://attack.mitre.org/groups/G0050) | `att&ck::G0050` | ('att&ck',) | [APT32](https://attack.mitre.org/groups/G0050) is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journalists with a strong focus on Southeast Asian countries like Vietnam, the Philippines, Laos, and Cambodia. They have extensively used strategic web compromises to compromise victims.(Citation: FireEye APT32 May 2017)(Citation: Volexity OceanLotus Nov 2017)(Citation: ESET OceanLotus) |
| APT32 | `misp::aa29ae56-e54b-47a2-ad16-d3ab0242d5d7` | ('misp',) | Cyber espionage actors, now designated by FireEye as APT32 (OceanLotus Group), are carrying out intrusions into private sector companies across multiple industries and have also targeted foreign governments, dissidents, and journalists. FireEye assesses that APT32 leverages a unique suite of fully-featured malware, in conjunction with commercially-available tools, to conduct targeted operations that are aligned with Vietnamese state interests. |
| [[Enterprise] Chimera](https://attack.mitre.org/groups/G0114) | `att&ck::G0114` | ('att&ck',) | [Chimera](https://attack.mitre.org/groups/G0114) is a suspected China-based threat group that has been active since at least 2018 targeting the semiconductor industry in Taiwan as well as data from the airline industry.(Citation: Cycraft Chimera April 2020)(Citation: NCC Group Chimera January 2021) |
| [[Enterprise] GALLIUM](https://attack.mitre.org/groups/G0093) | `att&ck::G0093` | ('att&ck',) | [GALLIUM](https://attack.mitre.org/groups/G0093) is a cyberespionage group that has been active since at least 2012, primarily targeting telecommunications companies, financial institutions, and government entities in Afghanistan, Australia, Belgium, Cambodia, Malaysia, Mozambique, the Philippines, Russia, and Vietnam. This group is particularly known for launching Operation Soft Cell, a long-term campaign targeting telecommunications providers.(Citation: Cybereason Soft Cell June 2019) Security researchers have identified [GALLIUM](https://attack.mitre.org/groups/G0093) as a likely Chinese state-sponsored group, based in part on tools used and TTPs commonly associated with Chinese threat actors.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)(Citation: Unit 42 PingPull Jun 2022) |
| GALLIUM | `misp::e400b6c5-77cf-453d-ba0f-44575583ac6c` | ('misp',) | GALLIUM, is a threat actor believed to be targeting telecommunication providers over the world, mostly South-East Asia, Europe and Africa. To compromise targeted networks, GALLIUM target unpatched internet-facing services using publicly available exploits and have been known to target vulnerabilities in WildFly/JBoss. |
| [[Enterprise] Kimsuky](https://attack.mitre.org/groups/G0094) | `att&ck::G0094` | ('att&ck',) | [Kimsuky](https://attack.mitre.org/groups/G0094) is a North Korea-based cyber espionage group that has been active since at least 2012. The group initially focused on targeting South Korean government entities, think tanks, and individuals identified as experts in various fields, and expanded its operations to include the UN and the government, education, business services, and manufacturing sectors in the United States, Japan, Russia, and Europe. [Kimsuky](https://attack.mitre.org/groups/G0094) has focused its intelligence collection activities on foreign policy and national security issues related to the Korean peninsula, nuclear policy, and sanctions. [Kimsuky](https://attack.mitre.org/groups/G0094) operations have overlapped with those of other North Korean cyber espionage actors likely as a result of ad hoc collaborations or other limited resource sharing.(Citation: EST Kimsuky April 2019)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: CISA AA20-301A Kimsuky)(Citation: Mandiant APT43 March 2024)(Citation: Proofpoint TA427 April 2024)  [Kimsuky](https://attack.mitre.org/groups/G0094) was assessed to be responsible for the 2014 Korea Hydro & Nuclear Power Co. compromise; other notable campaigns include Operation STOLEN PENCIL (2018), Operation Kabar Cobra (2019), and Operation Smoke Screen (2019).(Citation: Netscout Stolen Pencil Dec 2018)(Citation: EST Kimsuky SmokeScreen April 2019)(Citation: AhnLab Kimsuky Kabar Cobra Feb 2019)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups.  In 2023, [Kimsuky](https://attack.mitre.org/groups/G0094) has used commercial large language models to assist with vulnerability research, scripting, social engineering and reconnaissance.(Citation: MSFT-AI) |
| TA406 | `misp::89f005f9-22e9-4c50-9b48-e94c521266e5` | ('misp',) | TA406 is engaging in malware distribution, phishing, intelligence collection, and cryptocurrency theft, resulting in a wide range of criminal activities. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1550.002` | [Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002) | Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.  When performing PtH, valid password hashes for the account being used are captured using a [Credential Access](https://attack.mitre.org/tactics/TA0006) technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.  Adversaries may also use stolen password hashes to "overpass the hash." Similar to PtH, this involves using a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket. This ticket can then be used to perform [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) attacks.(Citation: Stealthbits Overpass-the-Hash) |
