# Malicious NSIS installer deployment

## Metadata
| Field | Value |
| --- | --- |
| UUID | `52462685-bebb-4e86-94b0-fd46aeacb085` |
| Schema | `threat::1.0` |
| Version | `1` |
| Created | `2026-02-09` |
| Modified | `2026-02-09` |
| TLP | clear (`TLP:CLEAR`) |
| Organisation | EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`) |

## References
### Public
- **1**: [https://securelist.com/notepad-supply-chain-attack/115382/](https://securelist.com/notepad-supply-chain-attack/115382/)
- **2**: [https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/](https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/)

## Description
## Overview

Malicious NSIS (Nullsoft Scriptable Install System) installers are being weaponized 
in supply chain attacks to deploy various payloads on victim systems. This technique 
was observed in the Notepad++ supply chain attack where three distinct infection 
chains leveraged NSIS installers with different payloads and behaviors.

## Technical Details

### NSIS Runtime Behavior

When executed, NSIS installers create a temporary directory at runtime:

```
%localappdata%\Temp\ns<random>.tmp
```

This directory creation is a key detection indicator for NSIS installer execution, 
both legitimate and malicious.

### Infection Chain #1 - ProShow Exploit (1MB Size)

**Behavior:**
- Sends heartbeat with system information to command and control
- Drops ProShow exploit payload
- Collects victim telemetry

**Indicators:**
- SHA1: 8e6e505438c21f3d281e1cc257abdbf7223b7f5a
- SHA1: 90e677d7ff5844407b9c073e3b7e896e078e11cd

### Infection Chain #2 - Lua Interpreter (140KB Size)

**Behavior:**
- Collects detailed system information
- Drops Lua interpreter with malicious script
- Establishes persistence mechanism

**Indicators:**
- SHA1: 573549869e84544e3ef253bdba79851dcde4963a
- SHA1: 13179c8f19fbf3d8473c49983a199e6cb4f318f0

### Infection Chain #3 - DLL Sideloading

**Behavior:**
- Drops BluetoothService DLL sideloading components
- Establishes stealth execution capability
- Maintains persistence via legitimate-looking service

**Indicators:**
- SHA1: 4c9aac447bf732acc97992290aa7a187b967ee2c
- SHA1: 821c0cafb2aab0f063ef7e313f64313fc81d46cd

## Detection Guidance

### File System Monitoring

Monitor for NSIS temporary directory creation patterns:

```
File Creation: %localappdata%\Temp\ns*.tmp\*
Parent Process: updater.exe, or unexpected processes
```

### Hash-Based Detection

Monitor for known malicious updater.exe hashes:
- 8e6e505438c21f3d281e1cc257abdbf7223b7f5a
- 90e677d7ff5844407b9c073e3b7e896e078e11cd
- 573549869e84544e3ef253bdba79851dcde4963a
- 13179c8f19fbf3d8473c49983a199e6cb4f318f0
- 4c9aac447bf732acc97992290aa7a187b967ee2c
- 821c0cafb2aab0f063ef7e313f64313fc81d46cd

### Behavioral Detection

1. **Unexpected NSIS Execution**
   - NSIS installers executing from unusual locations
   - User directories, temp folders, browser cache

2. **Network Communication**
   - Outbound connections from installer processes
   - Heartbeat traffic with system telemetry

3. **Payload Dropping**
   - Lua interpreter deployment in non-standard locations
   - DLL files dropped alongside legitimate executables
   - ProShow-related files in unexpected directories

### Process Monitoring

```
Process: *.exe
CommandLine Contains: "updater.exe"
File Size: 140KB or 1MB (typical malicious sizes)
Parent Process: explorer.exe, browser processes
Child Processes: lua.exe, rundll32.exe, regsvr32.exe
```

## Mitigation Recommendations

1. **Software Update Controls**
   - Verify digital signatures on all installers
   - Implement application control policies
   - Whitelist legitimate update mechanisms

2. **Network Segmentation**
   - Restrict outbound connections from installer processes
   - Monitor C2 communication patterns

3. **Endpoint Detection**
   - Deploy EDR solutions with NSIS installer monitoring
   - Alert on ns*.tmp directory creation from suspicious processes

4. **User Awareness**
   - Train users to verify software sources
   - Warn against running installers from unexpected locations
   - Implement prompt for administrator approval on installations

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
Targeted systems are Windows-based workstations and laptops where legitimate software 
update mechanisms exist. The attack leverages NSIS (Nullsoft Scriptable Install System) 
installers to masquerade as legitimate software updates, particularly targeting 
developer environments and end-user workstations. The NSIS framework creates temporary 
directories during runtime that can serve as indicators of compromise.

## Surface
> **Windows::Desktop**
> Microsoft Windows desktop editions

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach<br>Lose Capabilities<br>Business disruption<br>Reputational Damages | Non-public information has been accessed from the outside, and successfully extracted.<br>Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss.<br>Business disruption<br>Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered. |
| Leverage | Software installation<br>Infrastructure Compromise<br>Tampering | Software installation or code modification<br>The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.<br>Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Execution | Techniques that result in execution of attacker-controlled code on a local or remote system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1204.002` | [User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002) | An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, .cpl, and .reg.  Adversaries may employ various forms of [Masquerading](https://attack.mitre.org/techniques/T1036) and [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to increase the likelihood that a user will open and successfully execute a malicious file. These methods may include using a familiar naming convention and/or password protecting the file and supplying instructions to a user on how to open it.(Citation: Password Protected Word Docs)   While [Malicious File](https://attack.mitre.org/techniques/T1204/002) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534). |
| `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).  There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).  Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python) |

## Chaining
```mermaid
flowchart LR
subgraph "Execution"
52462685_bebb_4e86_94b0_fd46aeacb085{{"Malicious NSIS installer<br>deployment"}}
end
subgraph "Delivery"
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22{{"Notepad++ supply chain<br>attack"}}
end
52462685_bebb_4e86_94b0_fd46aeacb085 -->|implements| 8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22
```
### Chaining details
#### implements -> [Notepad++ supply chain attack](notepad-supply-chain-attack.md) (`8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22`) (`atomicity::implements`)
This threat vector implements the Notepad++ supply chain attack campaign,
where malicious NSIS installers were distributed through compromised update mechanisms.

- **Target UUID**: `8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22`

## Coverage
```mermaid
flowchart TB
subgraph "Objectives"
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d(["Detect Notepad++ Supply<br>Chain Compromise<br>Activity"])
end
subgraph "Threats"
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22{{"Notepad++ supply chain<br>attack"}}
23d06aa7_f6d5_44ee_be8f_e6de2f495bd9{{"ProShow vulnerability<br>exploitation for payload<br>delivery"}}
bc365789_bdbb_4e78_b2ae_b097a7ccd35f{{"Lua interpreter<br>shellcode execution"}}
bc95c747_ede2_4c16_a6b4_506b305e744a{{"Chrysalis backdoor<br>deployment via DLL<br>sideloading"}}
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a{{"Cobalt Strike Beacon<br>deployment via<br>Metasploit downloader"}}
bee6e973_b0d0_4735_a26a_003f39b8c08d{{"System reconnaissance<br>via shell commands in<br>supply chain attack"}}
bf30d882_9b96_403a_9a47_83a2981fc526{{"LOLC2 service abuse via<br>temp.sh"}}
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad{{"Registry autorun<br>persistence from<br>temporary folders"}}
end
subgraph "Signals"
8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d(("NSIS Installer<br>Deployment from<br>Notepad++ Updater"))
2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c(("System Reconnaissance<br>Commands Following<br>Software Update"))
6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d(("Data Exfiltration to<br>temp.sh Web Service"))
4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d(("Suspicious DLL<br>Side-Loading and<br>Exploit-Based Execution"))
9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d(("Cobalt Strike Beacon C2<br>Communication"))
end
52462685_bebb_4e86_94b0_fd46aeacb085{{"Malicious NSIS installer<br>deployment"}}
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22 -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
52462685_bebb_4e86_94b0_fd46aeacb085 -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
23d06aa7_f6d5_44ee_be8f_e6de2f495bd9 -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
bc365789_bdbb_4e78_b2ae_b097a7ccd35f -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
bc95c747_ede2_4c16_a6b4_506b305e744a -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
bee6e973_b0d0_4735_a26a_003f39b8c08d -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
bf30d882_9b96_403a_9a47_83a2981fc526 -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
55eaa437_5a25_4c29_b1fc_9c0fba4a18ad -->|covers| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d --> 8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d --> 2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d --> 6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d --> 4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d --> 9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d
```
## Related objects
| Type | Name | Direction | Relation |
| --- | --- | --- | --- |
| Objective | [Detect Notepad++ Supply Chain Compromise Activity](../Objectives/detect-notepad-supply-chain-compromise-activity.md) (`3e8b5d7f-9c2a-4f6e-8b1d-7a4c9e3f6b2d`) | Downstream | objective |
| Signal | [System Reconnaissance Commands Following Software Update](../Objectives/detect-notepad-supply-chain-compromise-activity.md#system-reconnaissance-commands-following-software-update) (`2f7c9b4e-8d3a-4e6f-9b1c-7a5d8e2f4b6c`) | Downstream | signal |
| Signal | [Suspicious DLL Side-Loading and Exploit-Based Execution](../Objectives/detect-notepad-supply-chain-compromise-activity.md#suspicious-dll-side-loading-and-exploit-based-execution) (`4e7b9d3f-6c2a-4e8f-9b1d-7a5c8e3f6b2d`) | Downstream | signal |
| Signal | [Data Exfiltration to temp.sh Web Service](../Objectives/detect-notepad-supply-chain-compromise-activity.md#data-exfiltration-to-temp-sh-web-service) (`6c9f3e7b-4d2a-4e8f-9b6d-3a7c5e1f8b4d`) | Downstream | signal |
| Signal | [NSIS Installer Deployment from Notepad++ Updater](../Objectives/detect-notepad-supply-chain-compromise-activity.md#nsis-installer-deployment-from-notepad-updater) (`8d4f6b2e-9c7a-4e1f-8b3d-6a9c5e7f2b4d`) | Downstream | signal |
| Signal | [Cobalt Strike Beacon C2 Communication](../Objectives/detect-notepad-supply-chain-compromise-activity.md#cobalt-strike-beacon-c2-communication) (`9b6e4d8f-7c3a-4e2f-8b1d-6a9c5e7f3b4d`) | Downstream | signal |
