# AppLocker enumerating policy bypass

## Metadata

- **UUID**: `9a1aeae5-912e-492c-b5d4-8bce91a95dae`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-07-11`
- **Modified**: `2025-07-11`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://oddvar.moe/2019/02/01/bypassing-applocker-as-an-admin](https://oddvar.moe/2019/02/01/bypassing-applocker-as-an-admin)
- **2**: [https://techyrick.com/applocker-bypass-windows-privilege-escalation](https://techyrick.com/applocker-bypass-windows-privilege-escalation)
- **3**: [https://learn.microsoft.com/en-us/visualstudio/msbuild/walkthrough-using-msbuild?view=vs-2022](https://learn.microsoft.com/en-us/visualstudio/msbuild/walkthrough-using-msbuild?view=vs-2022)
- **4**: [https://deepwiki.com/peass-ng/PEASS-ng/3-winpeas](https://deepwiki.com/peass-ng/PEASS-ng/3-winpeas)
- **5**: [https://securitycafe.ro/2023/05/02/bypassing-application-whitelisting](https://securitycafe.ro/2023/05/02/bypassing-application-whitelisting)
- **6**: [https://mycloudnet.wordpress.com/2015/08/20/verify-applocker-settings-in-the-registry](https://mycloudnet.wordpress.com/2015/08/20/verify-applocker-settings-in-the-registry)
- **7**: [https://medium.com/@Idabian/abusing-applocker-misconfigurations-powershell-without-powershell-part-2-24d61ce3202f](https://medium.com/@Idabian/abusing-applocker-misconfigurations-powershell-without-powershell-part-2-24d61ce3202f)

## Description
Enumerating policy bypass in AppLocker refers to the process of identifying
and exploiting weaknesses or vulnerabilities in AppLocker policies to run
unauthorised applications.    

A threat actor can use various methods and tools to enumerate AppLocker
policies with the goal to find weaknesses in this protection mechanism and
to exploit its whitelisting. Some of them are listed below.

### Bypass AppLocker policies

- Renaming executables method - renaming malicious executables to match the
name of an allowed application. In this way a threat actor can hide their
real malicious executables and intend in order to bypass AppLocker policies. 
- Using alternative executable extensions - using alternative executable
extensions, such as .scr or .pif, to bypass AppLocker rules.
- Enumeration of AppLocker policies tools - a threat actor can use different
enumeration tools to check if AppLocker policies are on place and what they
are blocking.

### Enumerating AppLocker policies

AppLocker policies can be enumerated using the registry query functionality,
as show below ref [5],[6]:  

'reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\'

### Known tools for AppLocker policy enumeration

AppLocker is a Windows feature that allows administrators to control which
applications can run on a device. Threat actors often try to bypass or
enumerate AppLocker policies to execute malicious code.

- PowerShell: PowerShell is a powerful tool that can be used to enumerate
AppLocker policies. Threat actors can use PowerShell cmdlets like
`Get-AppLockerPolicy` to retrieve AppLocker policies and
`Test-AppLockerPolicy` to test whether a specific application is allowed
to run.
- AppLocker Bypass Tools: There are several tools available online that can
bypass AppLocker policies. For example, the tool named `AppLockerBypass` is
a tool that uses various techniques to bypass AppLocker policies. Another
tool used for this purpose is `BypassAppLocker`. This tool uses PowerShell
to bypass AppLocker policies.
- MSBuild: MSBuild is a legitimate Windows utility that can be used to build
and execute code. Threat actors can use MSBuild to bypass AppLocker policies
by executing malicious code.
- Rundll32 : RunDLL is a legitimate Windows utility that can be used to execute
dll. Threat actors can use RunDLL to bypass AppLocker policies.
- Regasm/Regsvr32: Regasm and Regsvr32 are legitimate Windows utilities that
can be used to register and execute DLLs. Threat actors can use these tools
to bypass AppLocker policies by executing malicious DLLs.
- Certutil: Certutil is a legitimate Windows utility that can be used to
manage certificates. Threat actors can use Certutil to bypass AppLocker
policies by executing malicious code.
- Wscript/Cscript: Wscript and Cscript are legitimate Windows utilities that
can be used to execute scripts. Threat actors can use these tools to bypass
AppLocker policies by executing malicious scripts.
- Invoke-AppLockerBypass: This is a PowerShell script that uses various
techniques to bypass AppLocker policies.
- SharpAppLocker: This is a C# tool that can be used to bypass AppLocker
policies.
- WinPEAS - WinPEAS is a powerful tool that can be used to audit and bypass
Windows security features, including AppLocker policies. For more details
related to WinPEAS Applocker enumeration usage check ref [2].

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor needs to have sufficient privileges to enumerate AppLocker
policies and initial access to the targeted system. 

Required level of privileges to enumerate SharpAppLocker could be one of
the listed below:

- Local Administrator or elevated privileges
- Access to the Windows Management Instrumentation (WMI) or Windows Registry
- Ability to execute PowerShell scripts or commands

Domains: Enterprise
Targets: Workstations, Customer, End-user, Laptop, Other
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Impairement; Data Breach; Lose Capabilities | - |
| Leverage | Elevation of privilege; Infrastructure Compromise; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1218` | [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218) | Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.(Citation: LOLBAS Project) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.  Similarly, on Linux systems adversaries may abuse trusted binaries such as <code>split</code> to proxy execution of malicious commands.(Citation: split man page)(Citation: GTFO split) |
