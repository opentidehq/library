# Possible Smart App Control Evasion Attempt

## Metadata

- **UUID**: `dcf021a5-2846-40b4-8189-2695a7a32b9a`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-06-12`
- **Modified**: `2025-06-24`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://thehackernews.com/2024/08/researchers-uncover-flaws-in-windows.html](https://thehackernews.com/2024/08/researchers-uncover-flaws-in-windows.html)
- **2**: [https://thecyberexpress.com/windows-smart-app-control-smartscreen-bypass/](https://thecyberexpress.com/windows-smart-app-control-smartscreen-bypass/)
- **3**: [https://www.securitynewspaper.com/2024/08/06/five-techniques-for-bypassing-microsoft-smartscreen-and-smart-app-control-sac-to-run-malware-in-windows/](https://www.securitynewspaper.com/2024/08/06/five-techniques-for-bypassing-microsoft-smartscreen-and-smart-app-control-sac-to-run-malware-in-windows/)
- **4**: [https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2/](https://www.ibm.com/think/x-force/bypassing-windows-defender-application-control-loki-c2/)

## Description
Smart App Control is a cloud-powered security feature in Windows 11 designed to 
block malicious, untrusted, and potentially unwanted applications from running. 
It uses a combination of reputation checks and digital signatures to determine whether 
an application is safe to execute. If an app is not recognized or is considered 
risky, SAC blocks its execution.

## Main Evasion Techniques

**1. Registry Manipulation**
Registry manipulation is a common method in broader Windows attack vectors for disabling 
or bypassing security features. Adversaries may attempt to:
- **Disable or modify SAC-related registry keys** to weaken or turn off the feature.
- **Tamper with security policy settings** stored in the registry to lower protection levels.
  
**2. Code-Signing and Certificate Abuse**
One of the most prevalent methods to bypass SAC is to sign malware with a legitimate 
code-signing certificate. Attackers increasingly use Extended Validation (EV) certificates, 
which require identity verification, by impersonating legitimate businesses to obtain 
them. This allows malware to appear trustworthy and slip past SAC’s checks.

**3. Reputation-Based Evasion**
- **Reputation Hijacking:** Attackers repurpose trusted applications (like script interpreters) 
to load and execute malicious code without triggering alerts.
- **Reputation Seeding:** Attackers use seemingly innocuous binaries to trigger 
malicious behavior after a certain time or event.
- **Reputation Tampering:** Attackers alter parts of legitimate binaries to inject 
shellcode without losing their good reputation.

**4. LNK Stomping**
Attackers exploit the way Windows handles shortcut (LNK) files. By crafting LNK 
files with non-standard target paths or structures, they can remove the "mark-of-the-web" 
(MotW) tag before security checks are performed, allowing malicious payloads to 
bypass SAC.

**5. Social Engineering**
Attackers trick users into overriding security warnings or disabling SAC by posing 
as legitimate sources or using persuasive tactics.

**6. Living-Off-The-Land Binaries (LOLBins)**
Attackers abuse signed Microsoft-supplied binaries (e.g., `mshta.exe`, 
`rundll32.exe`, `regsvr32.exe`) to proxy execution of malicious scripts 
and payloads, which Smart App Control might not block if the binary is 
considered trusted.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adverdaries need to sign malware with a legitimate or fraudulently obtained code-signing 
certificate—especially Extended Validation (EV) certificates.

Domains: Enterprise, OSINT
Targets: Workstations, Public-Facing Servers, Virtual Machines, Software Containers, Windows API, Critical Documents
Platforms: Windows, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Monetary Loss; Business disruption | - |
| Leverage | Spoofing; Tampering; Elevation of privilege; Information Disclosure; Modify configuration; Modify privileges; Modify data | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1112` | [Modify Registry](https://attack.mitre.org/techniques/T1112) | Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.  Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification.(Citation: Microsoft Reg) Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API.  The Registry may be modified in order to hide configuration information or malicious payloads via [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027).(Citation: Unit42 BabyShark Feb 2019)(Citation: Avaddon Ransomware 2021)(Citation: Microsoft BlackCat Jun 2022)(Citation: CISA Russian Gov Critical Infra 2018) The Registry may also be modified to [Impair Defenses](https://attack.mitre.org/techniques/T1562), such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory.(Citation: CISA LockBit 2023)(Citation: Unit42 BabyShark Feb 2019)  The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system.(Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.  Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API.(Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.(Citation: TrendMicro POWELIKS AUG 2014)(Citation: SpectorOps Hiding Reg Jul 2017) |
| `T1195` | [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) | Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.  Supply chain compromise can take place at any stage of the supply chain including:  * Manipulation of development tools * Manipulation of a development environment * Manipulation of source code repositories (public or private) * Manipulation of source code in open-source dependencies * Manipulation of software update/distribution mechanisms * Compromised/infected system images (multiple cases of removable media infected at the factory)(Citation: IBM Storwize)(Citation: Schneider Electric USB Malware)  * Replacement of legitimate software with modified versions * Sales of modified/counterfeit products to legitimate distributors * Shipment interdiction  While supply chain compromise can impact any component of hardware or software, adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.(Citation: Avast CCleaner3 2018)(Citation: Microsoft Dofoil 2018)(Citation: Command Five SK 2011) Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.(Citation: Symantec Elderwood Sept 2012)(Citation: Avast CCleaner3 2018)(Citation: Command Five SK 2011) Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise) |
| `T1204` | [User Execution](https://attack.mitre.org/techniques/T1204) | An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of [Phishing](https://attack.mitre.org/techniques/T1566).  While [User Execution](https://attack.mitre.org/techniques/T1204) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).  Adversaries may also deceive users into performing actions such as:  * Enabling [Remote Access Tools](https://attack.mitre.org/techniques/T1219), allowing direct control of the system to the adversary * Running malicious JavaScript in their browser, allowing adversaries to [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539)s(Citation: Talos Roblox Scam 2023)(Citation: Krebs Discord Bookmarks 2023) * Downloading and executing malware for [User Execution](https://attack.mitre.org/techniques/T1204) * Coerceing users to copy, paste, and execute malicious code manually(Citation: Reliaquest-execution)(Citation: proofpoint-selfpwn)  For example, tech support scams can be facilitated through [Phishing](https://attack.mitre.org/techniques/T1566), vishing, or various forms of user interaction. Adversaries can use a combination of these methods, such as spoofing and promoting toll-free numbers or call centers that are used to direct victims to malicious websites, to deliver and execute payloads containing malware or [Remote Access Tools](https://attack.mitre.org/techniques/T1219).(Citation: Telephone Attack Delivery) |
