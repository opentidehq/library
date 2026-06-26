# AppLocker bypass using writable folders

## Metadata

- **UUID**: `ff8c52ac-77d0-4bee-9f6d-e40fc6e0da63`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-07-14`
- **Modified**: `2025-07-15`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://techyrick.com/applocker-bypass-windows-privilege-escalation](https://techyrick.com/applocker-bypass-windows-privilege-escalation)
- **2**: [https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)
- **3**: [https://www.windowscentral.com/software-apps/windows-11/what-is-the-appdata-folder-windows-11-app-data-storage-explained](https://www.windowscentral.com/software-apps/windows-11/what-is-the-appdata-folder-windows-11-app-data-storage-explained)
- **4**: [https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid?redirectedfrom=MSDN#roaming](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid?redirectedfrom=MSDN#roaming)
- **5**: [https://www.reddit.com/r/sysadmin/comments/dvu43i/psa_applocker_default_rules_can_be_easily_bypassed](https://www.reddit.com/r/sysadmin/comments/dvu43i/psa_applocker_default_rules_can_be_easily_bypassed)
- **6**: [https://gist.github.com/egre55/6b91444b8da8ccff65a9670a334fc05d](https://gist.github.com/egre55/6b91444b8da8ccff65a9670a334fc05d)
- **7**: [https://cybersecuritynews.com/writable-file-in-lenovos-windows-directory](https://cybersecuritynews.com/writable-file-in-lenovos-windows-directory)

## Description
AppLocker bypass using writable folders is a technique where an attacker
exploits the fact that AppLocker only checks the executable file's path,
not the path of the folder containing the executable. By placing a malicious
executable in a writable folder that is not restricted by AppLocker, an
attacker can bypass AppLocker controls.  

AppLocker uses a set of rules to determine which applications are allowed
to run. These rules are based on factors like the application's path,
publisher, and hash. If a threat actor can write to a folder that is allowed
by AppLocker, they can potentially bypass the restrictions.  

### Examples for AppLocker writable folders

The list below includes some of the folders in Windows where a standard user
have write permissions by default. These permissions can be used by threat
actors and let them to bypass AppLocker Windows whitelisting functionality.
For more information please check ref [1], [2].  

- `C:\Windows\Tasks` - Windows Tasks directory, writable by the "Users" group
- `C:\Windows\Temp`  - Temporary Files
- `C:\Windows\tracing`
- `C:\Windows\Registration\CRMLog`
- `C:\Windows\System32\FxsTmp`
- `C:\Windows\System32\com\dmp`
- `C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys`
- `C:\Windows\System32\spool\PRINTERS`
- `C:\Windows\System32\spool\SERVERS`
- `C:\Windows\System32\spool\drivers\color`
- `C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter`
- `C:\Windows\System32\Tasks_Migrated`
   (after peforming a version upgrade of Windows 10)
- `C:\Windows\SysWOW64\FxsTmp`
- `C:\Windows\SysWOW64\com\dmp`
- `C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter`
- `C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System`

Additional ref [3], [4]:

- `%APPDATA%`                        # Application Data / Roaming User Data
- `%LOCALAPPDATA%`                   # Local Application Data / Local User Data
- `%USERPROFILE%\Desktop`            # User's Desktop): Desktop
- `%USERPROFILE%\AppData\Local\Temp` # Local Low, this is a subfolder of %LOCALAPPDATA%

### Other possible writable folders in AppLocker

There are some other possible writable folders in `C:\WINDOWS` where a
standard Windows user may have write permissions by default. For example,
'accesschk.exe' from Sysinternals Suite can be used to find folders that
are writable and can be leveraged. Furthermore, 'icacls.exe' can be used to
determine if we also have execute rights within the targeted folder.

Different threat actors are actively exploiting this AppLocker bypass
technique to deploy malware, execute malicious code, and gain persistence
on compromised systems.

### Example

Lenovo devices include a file, MFGSTAT.zip, in C:\\Windows that is writable
by authenticated users. An attacker can embed a malicious payload into an
NTFS alternate data stream within this ZIP file and invoke it via a signed
Windows binary (e.g., AppVLP.exe), bypassing AppLocker rules.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor needs and initial access to a Windows system and user's write
permissions where AppLocker policies allow execution from common writable
directories like C:\\Windows\\Temp or Tasks.

Domains: Enterprise
Targets: Workstations, End-user, Customer
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Impairement; Data Breach; Business disruption; Lose Capabilities; Reputational Damages | - |
| Leverage | Elevation of privilege; Infrastructure Compromise; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Lazarus Group](https://attack.mitre.org/groups/G0032) | `att&ck::G0032` | ('att&ck',) | [Lazarus Group](https://attack.mitre.org/groups/G0032) is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.(Citation: US-CERT HIDDEN COBRA June 2017)(Citation: Treasury North Korean Cyber Groups September 2019) The group has been active since at least 2009 and was reportedly responsible for the November 2014 destructive wiper attack against Sony Pictures Entertainment as part of a campaign named Operation Blockbuster by Novetta. Malware used by [Lazarus Group](https://attack.mitre.org/groups/G0032) correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.(Citation: Novetta Blockbuster)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups, such as [Andariel](https://attack.mitre.org/groups/G0138), [APT37](https://attack.mitre.org/groups/G0067), [APT38](https://attack.mitre.org/groups/G0082), and [Kimsuky](https://attack.mitre.org/groups/G0094). |
| Lazarus Group | `misp::68391641-859f-4a9a-9a1e-3e5cf71ec376` | ('misp',) | Since 2009, HIDDEN COBRA actors have leveraged their capabilities to target and compromise a range of victims; some intrusions have resulted in the exfiltration of data while others have been disruptive in nature. Commercial reporting has referred to this activity as Lazarus Group and Guardians of Peace. Tools and capabilities used by HIDDEN COBRA actors include DDoS botnets, keyloggers, remote access tools (RATs), and wiper malware. Variants of malware and tools used by HIDDEN COBRA actors include Destover, Duuzer, and Hangman. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1218` | [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218) | Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.(Citation: LOLBAS Project) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.  Similarly, on Linux systems adversaries may abuse trusted binaries such as <code>split</code> to proxy execution of malicious commands.(Citation: split man page)(Citation: GTFO split) |
