# Windows Explorer Manipulation via Registry Modification

## Metadata

- **UUID**: `8e5c12f1-cd48-417c-a9c9-883212bf98b6`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-07-11`
- **Modified**: `2025-07-16`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html)
- **2**: [https://vms.drweb.com/virus/?i=27670435](https://vms.drweb.com/virus/?i=27670435)
- **3**: [https://www.crowdstrike.com/en-us/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.crowdstrike.com/en-us/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)

## Description
Explorer behaviour can be twisted by editing the registry keys
listed below. Changes act instantly, leave few artefacts, and
are often missed by file-centric defenses.

### Policy Edits Disable User Defenses
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer  
Setting `DisableTaskMgr`, `DisableRegistryTools`, `NoViewOnDrive` or
NoFind stops Task Manager, Regedit, search and drive browsing,
blinding users.
Setting `NavPaneShowAllFolders` or `NavPaneExpandToCurrentFolder` can 
modify the navigation pane.
When set to 0, this value hides certain folders in the navigation pane, 
such as system folders or folders that are not typically displayed,
making it difficult for users to detect malicious activity.
When set to 1, this value shows all folders in the navigation pane, 
including hidden and system folders, making it harder for users to 
distinguish between legitimate and malicious files or folders.

### Advanced Flags Hide Artefacts
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  
Flipping Hidden, ShowSuperHidden or SuperHidden hides system
files and payloads, thwarting GUI-based hunting.

### User Shell Redirection
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders  
Replacing Desktop, Startup or Personal paths diverts files or
autoruns to attacker-controlled folders for theft or persistence.

### System-Wide Folder Hijack
- HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders  
System-level redirection funnels all users' documents and
shortcuts to rogue directories, enabling broad data capture.

### Global Advanced Flags Override
- HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  
Modifying the machine hive mirrors the HKCU tweaks but forces
hidden-file suppression and other changes on every profile.

### Environment Variable Hijack
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders  
Altering %APPDATA%, %TEMP% or %DESKTOP% variables tricks apps
into saving data or loading DLLs from malicious locations.

### Namespace Injection
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace  
Creating fake CLSID subkeys inserts rogue folders in Explorer,
luring users to launch payloads masked as system objects.

### Drive AutoRun Seeds
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2    
Inserting AutoRun and command entries forces code execution
whenever a specific USB or network share is browsed.

### Default Shell Replacement
- HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell  
Repointing the Shell value swaps explorer.exe for a malicious
binary, gaining control each time a user signs in.

### Enabling AutoPlay for Malicious Devices
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers  
Changing the `DeviceType` or `Handler` settings can enable AutoPlay for specific 
devices, such as network shares, potentially executing malicious code.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversary must obtain write access to the user-hive (HKCU) or,
for broader impact, administrative rights to HKLM and the
ability to execute **reg.exe**, PowerShell, or equivalent APIs on
Windows 7 - 11 workstations joined to Active Directory.

Domains: Enterprise
Targets: Workstations, Desktop, Laptop, Virtual Machines, Windows API
Platforms: Windows, Active Directory, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Impairement; Data Breach; Business disruption; Reputational Damages | - |
| Leverage | Tampering; Modify configuration; Modify data; Elevation of privilege | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Wizard Spider](https://attack.mitre.org/groups/G0102) | `att&ck::G0102` | ('att&ck',) | [Wizard Spider](https://attack.mitre.org/groups/G0102) is a Russia-based financially motivated threat group originally known for the creation and deployment of [TrickBot](https://attack.mitre.org/software/S0266) since at least 2016. [Wizard Spider](https://attack.mitre.org/groups/G0102) possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.(Citation: CrowdStrike Ryuk January 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: CrowdStrike Wizard Spider October 2020) |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1112` | [Modify Registry](https://attack.mitre.org/techniques/T1112) | Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.  Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification.(Citation: Microsoft Reg) Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API.  The Registry may be modified in order to hide configuration information or malicious payloads via [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027).(Citation: Unit42 BabyShark Feb 2019)(Citation: Avaddon Ransomware 2021)(Citation: Microsoft BlackCat Jun 2022)(Citation: CISA Russian Gov Critical Infra 2018) The Registry may also be modified to [Impair Defenses](https://attack.mitre.org/techniques/T1562), such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory.(Citation: CISA LockBit 2023)(Citation: Unit42 BabyShark Feb 2019)  The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system.(Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.  Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API.(Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.(Citation: TrendMicro POWELIKS AUG 2014)(Citation: SpectorOps Hiding Reg Jul 2017) |
| `T1547.001` | [Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) | Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.(Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.  The following run keys are created by default on Windows systems:  * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>  Run keys may exist under multiple hives.(Citation: Microsoft Wow6432Node 2018)(Citation: Malwarebytes Wow6432Node 2016) The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency.(Citation: Microsoft Run Key) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)  Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\Users\\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</code>. The startup folder path for all users is <code>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</code>.  The following Registry keys can be used to set startup folder items for persistence:  * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code> * <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code> * <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>  The following Registry keys can control automatic startup of services during boot:  * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>  Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:  * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>  Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run automatically for the currently logged-on user.  By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.  Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs. |
