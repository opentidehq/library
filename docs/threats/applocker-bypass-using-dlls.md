# AppLocker bypass using DLLs

## Metadata

- **UUID**: `a73c2506-8584-4c0b-bfdc-52e33c8bd229`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-07-10`
- **Modified**: `2025-07-10`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://umsundu.co.uk/posts/Breaking-Windows-Bypassing-AppLocker-When-PowerShell-and-CMD-Are-Locked-Down](https://umsundu.co.uk/posts/Breaking-Windows-Bypassing-AppLocker-When-PowerShell-and-CMD-Are-Locked-Down)
- **2**: [https://security.stackexchange.com/questions/183021/how-does-this-applocker-bypass-work-exactly-squibblydoo](https://security.stackexchange.com/questions/183021/how-does-this-applocker-bypass-work-exactly-squibblydoo)
- **3**: [https://insights.sei.cmu.edu/blog/bypassing-application-whitelisting](https://insights.sei.cmu.edu/blog/bypassing-application-whitelisting)
- **4**: [https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/dll-rules-in-applocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/dll-rules-in-applocker)
- **5**: [https://www.cyberis.com/article/cve-2021-20047-dll-search-order-hijacking-vulnerability](https://www.cyberis.com/article/cve-2021-20047-dll-search-order-hijacking-vulnerability)
- **6**: [https://medium.com/@Idabian/abusing-applocker-misconfigurations-powershell-without-powershell-part-2-24d61ce3202f](https://medium.com/@Idabian/abusing-applocker-misconfigurations-powershell-without-powershell-part-2-24d61ce3202f)
- **7**: [https://www.csoonline.com/article/1311082/north-koreas-lazarus-deploys-rootkit-via-applocker-zero-day-flaw.html](https://www.csoonline.com/article/1311082/north-koreas-lazarus-deploys-rootkit-via-applocker-zero-day-flaw.html)
- **8**: [https://www.securityweek.com/windows-zero-day-exploited-by-north-korean-hackers-in-rootkit-attack](https://www.securityweek.com/windows-zero-day-exploited-by-north-korean-hackers-in-rootkit-attack)

## Description
AppLocker bypass using DLLs involves exploiting the way Windows loads DLLs
into processes. An attacker can create a malicious DLL that mimics a
legitimate one, which is allowed to run by AppLocker. When a legitimate
application loads the malicious DLL, it can execute arbitrary code,
effectively bypassing AppLocker restrictions.

A threat actor can bypass AppLocker application whitelisting using DLL
libraries. The reason is that there is no a mechanism for blocking out some
of the default DLLs. 

Additionally, DLLs are not executed directly by the operating system;
instead, they are loaded into the memory space of a process. This makes
it challenging for AppLocker to detect and block malicious DLLs activities.

There are several techniques that can be used to bypass AppLocker
using DLLs:

- DLL Hijacking - a threat actor can create a malicious DLL with the same
  name as a legitimate DLL that is already allowed by AppLocker. When the
  legitimate application loads the DLL, it will load the malicious one
  instead, allowing the attacker to execute arbitrary code.
- DLL Preloading - a threat actor can create a malicious DLL that is loaded
  before the legitimate DLL. This can be done by placing the malicious DLL in
  a directory that is searched before the directory containing the legitimate
  DLL.
- DLL Side-Loading: An attacker can create a malicious DLL that is loaded by
  a legitimate application that is allowed by AppLocker. The malicious DLL can
  then execute arbitrary code.

### DLL hijacking mimics a legitimate DLL name in AppLocker

An attacker can create a malicious DLL with the same name as a legitimate
one, which is allowed to run by AppLocker. The malicious DLL is placed in a
directory that is searched before the legitimate DLL's location.

### Loading a malicious DLL

When a legitimate application loads the malicious DLL, Windows will load the
malicious DLL instead of the legitimate one. This allows the attacker to
execute arbitrary code, bypassing AppLocker restrictions.

### REGSRV32 binary can bypass AppLocker restrictions by executing malicious DLL

Regsvr32.exe is a trusted Windows binary which can be used to bypass
AppLocker restrictions by executing a malicious DLL (e.g., cmd.dll).
Since regsvr32.exe is typically allowed by AppLocker policies and doesn't
rely on cmd.exe or powershell.exe, it can be used to load and run arbitrary
code through exported functions like `DllRegisterServer`. This allows
attackers to execute commands or scripts while avoiding detection and
bypassing common application whitelisting controls ref [1].

### An example of AppLocker bypass using DLLs

As an example to bypass Windows AppLocker a threat actor can create a
malicious DLL named `search.dll` and place it in the `C:\Windows` directory.
When the Windows Search service loads the `search.dll` DLL, it will load the
malicious one instead of the legitimate one.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **The target must be a Windows environment with AppLocker enabled in
whitelisting mode. The attacker requires initial code execution on the
system (e.g., via phishing or exploit) and the ability to drop or register
a DLL alongside a permitted LOLbin.

Domains: Enterprise
Targets: Laptop, Workstations, Customer, End-user
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Business disruption; Impairement; Legal and regulatory; Data Breach; Lose Capabilities | - |
| Leverage | Elevation of privilege; Infrastructure Compromise; Information Disclosure; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |
| [[Enterprise] Lazarus Group](https://attack.mitre.org/groups/G0032) | `att&ck::G0032` | ('att&ck',) | [Lazarus Group](https://attack.mitre.org/groups/G0032) is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.(Citation: US-CERT HIDDEN COBRA June 2017)(Citation: Treasury North Korean Cyber Groups September 2019) The group has been active since at least 2009 and was reportedly responsible for the November 2014 destructive wiper attack against Sony Pictures Entertainment as part of a campaign named Operation Blockbuster by Novetta. Malware used by [Lazarus Group](https://attack.mitre.org/groups/G0032) correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.(Citation: Novetta Blockbuster)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups, such as [Andariel](https://attack.mitre.org/groups/G0138), [APT37](https://attack.mitre.org/groups/G0067), [APT38](https://attack.mitre.org/groups/G0082), and [Kimsuky](https://attack.mitre.org/groups/G0094). |
| Lazarus Group | `misp::68391641-859f-4a9a-9a1e-3e5cf71ec376` | ('misp',) | Since 2009, HIDDEN COBRA actors have leveraged their capabilities to target and compromise a range of victims; some intrusions have resulted in the exfiltration of data while others have been disruptive in nature. Commercial reporting has referred to this activity as Lazarus Group and Guardians of Peace. Tools and capabilities used by HIDDEN COBRA actors include DDoS botnets, keyloggers, remote access tools (RATs), and wiper malware. Variants of malware and tools used by HIDDEN COBRA actors include Destover, Duuzer, and Hangman. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1218` | [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218) | Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.(Citation: LOLBAS Project) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.  Similarly, on Linux systems adversaries may abuse trusted binaries such as <code>split</code> to proxy execution of malicious commands.(Citation: split man page)(Citation: GTFO split) |
