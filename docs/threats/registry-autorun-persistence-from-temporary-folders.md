# Registry autorun persistence from temporary folders

## Metadata

- **UUID**: `55eaa437-5a25-4c29-b1fc-9c0fba4a18ad`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2026-02-09`
- **Modified**: `2026-02-09`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://securelist.com/notepad-supply-chain-attack/115382/](https://securelist.com/notepad-supply-chain-attack/115382/)
- **2**: [https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/](https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/)
- **3**: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)

## Description
## Overview

This threat vector describes a Windows persistence technique that combines two
suspicious behaviors: dropping malicious executables into temporary/roaming 
application data folders (%appdata%) and establishing persistence through the
Windows registry autorun mechanism via Run keys. This technique ensures that
malicious programs start automatically when a user logs in, allowing attackers
to maintain access across system reboots.

## Attack Mechanism

The persistence technique follows a multi-step pattern:

1. **Payload Deployment**: Malicious files are dropped to unusual locations 
   within the user's application data directories, typically:
   - `%appdata%\ProShow\`
   - `%appdata%\Adobe\Scripts\`
   - `%appdata%\Bluetooth\`
   
2. **Registry Modification**: The attacker adds entries to the Windows Registry
   Run key at:
   - `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   
3. **Persistence Establishment**: The registry entries point directly to the
   malicious executables in the temporary/appdata locations, ensuring automatic
   execution at user logon.

## Why This Pattern is Suspicious

According to Kaspersky security researchers, "In this case, a clear sign of 
malicious activity is gaining persistence through the autorun mechanism via the 
Windows registry, specifically the Run key, which ensures that programs start 
automatically when the user logs in."

The combination of these behaviors is particularly suspicious because:

- **Legitimate software rarely uses %appdata% for persistence**: Well-designed
  applications typically install to Program Files and use proper installer mechanisms
- **Temporary folders indicate ephemeral content**: %appdata% subdirectories are
  generally used for user-specific configuration data, not executable programs
- **Run key pointing to temporary locations**: Legitimate autostart entries
  typically reference stable installation paths in system directories

## Detection Approach: temporary_folder_in_registry_autorun

Kaspersky KEDR Expert detection system identifies this activity through the
`temporary_folder_in_registry_autorun` rule, which specifically looks for:

1. Registry autorun entries (Run keys) being created or modified
2. The target path of these entries pointing to:
   - %appdata% subdirectories
   - Roaming profile directories
   - Other temporary/cache locations
3. Executable files residing in these non-standard locations

### Detection Logic

The detection rule triggers when:
- A new registry value is created in autorun keys (Run/RunOnce)
- The value data contains a path to %appdata% or similar temporary directories
- The referenced file is an executable (PE file, script, or DLL)

### Observed Malicious File Paths

In the Notepad++ supply chain attack, the following suspicious paths were observed:

```
%appdata%\ProShow\load
%appdata%\Adobe\Scripts\alien.ini
%appdata%\Bluetooth\BluetoothService
```

These paths exhibit clear indicators of compromise:
- **ProShow**: Not a legitimate ProShow installation directory
- **Adobe\Scripts**: Unusual location for Adobe scripting components
- **Bluetooth**: Mimics legitimate Windows Bluetooth services but resides in user profile

## Technical Details

### Registry Keys Targeted

```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

### Typical Registry Entry Format

```
Name: <Random or legitimate-looking name>
Type: REG_SZ
Data: C:\Users\<username>\AppData\Roaming\<subfolder>\<malicious.exe>
```

### Execution Flow

1. User logs into Windows
2. Windows reads registry Run keys during logon process
3. Windows executes all programs referenced in Run keys
4. Malicious payload launches automatically with user privileges
5. Malware establishes C2 communication and executes its objectives

## Detection Opportunities

### File System Monitoring

Monitor for suspicious file creation patterns:
- Executable files dropped to %appdata% subdirectories
- Particularly focus on non-standard subdirectory names (ProShow, Adobe\Scripts, Bluetooth)
- Files with misleading names mimicking legitimate software

### Registry Monitoring

Monitor registry operations:
- Creation/modification of values under Run/RunOnce keys
- Specifically flag entries pointing to %appdata%, %temp%, or %localappdata%
- Alert on registry changes made by non-installer processes

### Behavioral Analysis

Look for behavioral chains:
- Network-downloaded file → %appdata% storage → Registry modification
- Installer execution → Suspicious subdirectory creation → Autorun registration
- Script execution → Binary deployment → Persistence establishment

## MITRE ATT&CK Mapping

**T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**

This technique directly maps to MITRE ATT&CK's description of persistence through
registry Run keys. Adversaries achieve persistence by adding programs to startup
folders or registry Run keys that execute at user logon.

**Key Characteristics**:
- **Tactic**: Persistence, Privilege Escalation
- **Privileges Required**: User (for HKCU keys)
- **Platforms**: Windows
- **Data Sources**: Command execution, file monitoring, registry monitoring, Windows registry key modification

## Mitigation Recommendations

### Detection Rules

Implement the following detection logic:

```
IF (Registry Key Modified OR Registry Value Created)
AND (Key Path CONTAINS "CurrentVersion\Run")
AND (Value Data CONTAINS "%appdata%" OR "%temp%" OR "%localappdata%")
THEN Alert: "Suspicious autorun persistence from temporary folder"
```

### Preventive Measures

1. **Registry Protection**: Enable registry protection features in EDR/EPP solutions
2. **Application Whitelisting**: Restrict execution from %appdata% locations
3. **User Education**: Train users to recognize suspicious installer behavior
4. **Monitoring**: Deploy the temporary_folder_in_registry_autorun detection rule
5. **Group Policy**: Consider restricting Run key modifications via Group Policy

### Response Actions

When this persistence technique is detected:

1. **Immediate Containment**:
   - Isolate affected endpoint from network
   - Prevent user logon to stop autorun execution
   - Create forensic disk image for analysis

2. **Investigation**:
   - Examine registry Run keys for suspicious entries
   - Check %appdata% subdirectories for malicious files
   - Review parent process that created registry entry
   - Search for lateral movement indicators
   - Check for associated C2 network connections

3. **Remediation**:
   - Delete malicious registry entries
   - Remove malicious files from %appdata% locations
   - Scan for additional persistence mechanisms
   - Reset user credentials
   - Apply security patches and updates

4. **Recovery**:
   - Monitor for re-infection attempts
   - Verify complete malware removal
   - Restore normal operations
   - Update detection rules based on IoCs

## Real-World Context: Notepad++ Supply Chain Attack

This persistence technique was actively exploited in the Notepad++ supply chain
compromise (June-December 2025), where attackers:

- Compromised legitimate Notepad++ update infrastructure
- Delivered malicious NSIS installers disguised as authentic updates
- Deployed payloads to suspicious %appdata% subdirectories
- Established persistence via registry Run keys
- Maintained access across multiple infection chains

The attack demonstrated sophisticated tradecraft by:
- Evolving payloads across three distinct infection chains
- Using legitimate-looking subdirectory names (ProShow, Adobe, Bluetooth)
- Combining multiple techniques for defense evasion
- Targeting government, financial, and IT service sectors globally

## Indicators of Compromise

### Registry IoCs

Monitor for registry values in Run keys pointing to:
```
*\AppData\Roaming\ProShow\*
*\AppData\Roaming\Adobe\Scripts\*
*\AppData\Roaming\Bluetooth\*
```

### File System IoCs

Check for suspicious files in:
```
%appdata%\ProShow\load
%appdata%\Adobe\Scripts\alien.ini
%appdata%\Bluetooth\BluetoothService
```

### Process IoCs

Watch for suspicious parent-child process relationships:
- NSIS installer → Registry modification process
- Non-installer process → Registry Run key modification
- Script interpreter → Executable creation in %appdata%

## Conclusion

Registry autorun persistence from temporary folders represents a high-confidence
indicator of malicious activity. The combination of autorun registry modifications
and temporary folder execution is rarely used by legitimate software and should
trigger immediate investigation. Organizations should implement the 
temporary_folder_in_registry_autorun detection rule and establish monitoring
for this specific behavioral pattern.

This technique's confirmation in the Notepad++ supply chain attack demonstrates
its active use by sophisticated threat actors and underscores the importance of
robust detection and response capabilities for registry-based persistence mechanisms.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Windows endpoints where attackers have successfully deployed malicious payloads
to temporary or roaming application data directories (%appdata%) and seek to
establish persistent execution across system reboots. This technique is particularly
effective against systems with limited security monitoring of registry autorun
mechanisms, especially when combined with execution from non-standard application
data locations that evade traditional security controls.

Surface: OS::Windows::Desktop**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Business disruption; Data Breach; Impairement | - |
| Leverage | Tampering; Elevation of privilege; Infrastructure Compromise | - |
| Viability | Almost certain | Nearly certain - 95-99% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1547.001` | [Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) | Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.(Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.  The following run keys are created by default on Windows systems:  * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>  Run keys may exist under multiple hives.(Citation: Microsoft Wow6432Node 2018)(Citation: Malwarebytes Wow6432Node 2016) The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency.(Citation: Microsoft Run Key) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)  Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\Users\\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</code>. The startup folder path for all users is <code>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</code>.  The following Registry keys can be used to set startup folder items for persistence:  * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code> * <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code> * <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>  The following Registry keys can control automatic startup of services during boot:  * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>  Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:  * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>  Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run automatically for the currently logged-on user.  By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.  Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs. |

## Chaining
```mermaid
flowchart LR
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad["Registry autorun persistence from temporary folders"]
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22["Notepad++ supply chain attack"]
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|atomicity::implements| 8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22
```
### Chaining details
#### implements -> Notepad++ supply chain attack (`atomicity::implements`)
This persistence technique was observed in the Notepad++ supply chain attack,
where attackers established persistence by adding registry Run key entries
pointing to malicious executables dropped in temporary %appdata% subdirectories.

- **Target UUID**: `8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22`

## Relations
```mermaid
flowchart TB
subgraph "Objective"
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d["Detect Notepad++ Supply Chain Compromise Activity"]
end
subgraph "Signal"
2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c["2f7c9b4e-8d3a-4e6f-9b1c-7a5d8e2f4b6c"]
4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d["4e7b9d3f-6c2a-4e8f-9b1d-7a5c8e3f6b2d"]
6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d["6c9f3e7b-4d2a-4e8f-9b6d-3a7c5e1f8b4d"]
8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d["8d4f6b2e-9c7a-4e1f-8b3d-6a9c5e7f2b4d"]
9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d["9b6e4d8f-7c3a-4e2f-8b1d-6a9c5e7f3b4d"]
end
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad["Registry autorun persistence from temporary folders"]
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|objective| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|signal| 2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|signal| 4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|signal| 6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|signal| 8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|signal| 9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d
```
