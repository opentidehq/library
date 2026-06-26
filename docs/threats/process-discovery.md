# Process discovery

## Metadata

- **UUID**: `cc7dd57f-8d9e-451f-8ec7-4bb2ad10e96c`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-02-04`
- **Modified**: `2025-02-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://medium.com/@stackzero/how-to-do-process-enumeration-an-alternative-way-stackzero-fad874477cda](https://medium.com/@stackzero/how-to-do-process-enumeration-an-alternative-way-stackzero-fad874477cda)
- **2**: [https://cyber-kill-chain.ch/techniques/T1057/](https://cyber-kill-chain.ch/techniques/T1057/)
- **3**: [https://infosecwriteups.com/common-tools-techniques-used-by-threat-actors-and-malware-part-i-deb05b664879](https://infosecwriteups.com/common-tools-techniques-used-by-threat-actors-and-malware-part-i-deb05b664879)

## Description
A process discovery refers to the process of identifying and analyzing
the running processes on a system or network. This involves gathering
information about the processes, such as their names, IDs, command
lines, and other relevant details ref [1].  

For example, in Windows environment, an adversary could obtain details
on running processes using the Tasklist utility via cmd or `Get-Process`
via PowerShell. Information about processes can also be extracted from
the output of Native API calls such as `CreateToolhelp32Snapshot`
ref [2].  

In Mac and Linux, this is accomplished with the ps command.
The threat actors may also opt to enumerate processes via /proc.

By analyzing the running processes on a system or network, the threat
actors can abuse process discovery functionality in some of the
following ways:  

### Living-off-the-Land (LOTL) techniques to identify potential targets 

The threat actors may abuse native tools (PowerShell, WMIC) to blend
in with normal activity, avoiding suspicion.    

### Used tools by threat actors for process discovery on a target system

#### 1. Tasklist (Windows built-in) 

This command-line tool is used to display a list of currently running
processes on a Windows system. Threat actors might use it to identify
potential targets for exploitation or to understand the system's
configuration.  

#### 2. Process Monitor (SysInternals)

Process Monitor can be used to verify if the browser or other service
is launched on a target system and with what level of privileges. This
tool can monitor what processes are running on the system.      

#### 3. PsExec (SysInternals) 

This tool allows users to execute processes remotely, but it can also
be used to list running processes on a target system. Threat actors
might use PsExec to gather information about the system's processes
without being detected.

#### 4. PowerShell (Windows built-in)

PowerShell is a powerful scripting language that can be used to
automate tasks, including process discovery. Threat actors might use
PowerShell cmdlets like Get-Process to list running processes on a
target system.  

#### 5. Windows Management Instrumentation functionality (Windows built-in)

Threat actors can abuse WMI (Windows Management Instrumentation) filters
in Windows for process discovery. Examples include running WMI queries
(e.g., WMIC) to retrieve information about running processes, Creating
WMI specific event filters to monitor process creation, modification
and other process related information. Threat actors also can utilize
WMI filters to execute queries that retrieve process information,
for example: such as `SELECT * FROM Win32_Process`.  

#### 6. ProcDump (SysInternals)

This tool is designed to capture and analyze process dumps, but it can
also be used to list running processes on a target system. Threat actors
might use ProcDump to gather information about the system's processes and
identify potential vulnerabilities.  

#### 7. Process Explorer (SysInternals)

This tool provides a detailed view of running processes, including their
memory usage, network connections, and system resources. Threat actors
might use Process Explorer to gather information about the system's
processes and identify potential targets for exploitation.  

#### 8. Cygwin or Linux tools (e.g., ps, top, htop)

If the target system has a Unix-like environment installed, threat actors
might use tools like ps, top, or htop to list running processes and gather
information about the system's configuration.  

#### 9. Meterpreter (Metasploit)

Meterpreter is a payload that can be used to exploit vulnerabilities and
gain access to a target system. It includes a range of tools, including
process discovery capabilities, that threat actors can use to gather
information about the system's processes.

#### 10. Cobalt Strike's Process List

Cobalt Strike is a commercial penetration testing tool that includes
a range of features, including process discovery. Threat actors might
use Cobalt Strike to list running processes on a target system and
identify potential targets for exploitation.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actors rely on exposed / public visible processes,
they can scan and gather information for a target.

Domains: Embedded, Private Cloud, Public Cloud
Targets: Customer, End-user, Workstations, Laptop, Public-Facing Servers, Web Application Servers
Platforms: Windows, Linux, macOS, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Business disruption; Lose Capabilities; Nuisance; Operating costs; Reputational Damages | - |
| Leverage | Dwelling; Elevation of privilege; Information Disclosure; Infrastructure Compromise; Software installation; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Discovery | Techniques that allow an attacker to gain knowledge about a system and its network environment. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1057` | [Process Discovery](https://attack.mitre.org/techniques/T1057) | Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.  In Windows environments, adversaries could obtain details on running processes using the [Tasklist](https://attack.mitre.org/software/S0057) utility via [cmd](https://attack.mitre.org/software/S0106) or <code>Get-Process</code> via [PowerShell](https://attack.mitre.org/techniques/T1059/001). Information about processes can also be extracted from the output of [Native API](https://attack.mitre.org/techniques/T1106) calls such as <code>CreateToolhelp32Snapshot</code>. In Mac and Linux, this is accomplished with the <code>ps</code> command. Adversaries may also opt to enumerate processes via `/proc`. ESXi also supports use of the `ps` command, as well as `esxcli system process list`.(Citation: Sygnia ESXi Ransomware 2025)(Citation: Crowdstrike Hypervisor Jackpotting Pt 2 2021)  On network devices, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `show processes` can be used to display current running processes.(Citation: US-CERT-TA18-106A)(Citation: show_processes_cisco_cmd) |
