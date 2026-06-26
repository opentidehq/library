# Scheduled task created on remote endpoint

## Metadata

- **UUID**: `d11bfb38-3a0c-4e38-a973-efa2da1e8a73`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-12-15`
- **Modified**: `2022-12-15`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://devblogs.microsoft.com/scripting/weekend-scripter-use-powershell-to-otely-create-scheduled-task-and-folder/](https://devblogs.microsoft.com/scripting/weekend-scripter-use-powershell-to-otely-create-scheduled-task-and-folder/)
- **2**: [https://redcanary.com/threat-detection-report/techniques/scheduled-task/](https://redcanary.com/threat-detection-report/techniques/scheduled-task/)
- **3**: [https://www.action1.com/how-to-different-ways-to-create-scheduled-task-otely/](https://www.action1.com/how-to-different-ways-to-create-scheduled-task-otely/)

## Description
Adversaries with access to the right credentials can create scheduled tasks 
remotely from an endpoint they control for malicious purposes, which often 
include outbound connections to attacker infrastructure, binary execution, 
achieve persistance or registry entry editing or creation, but in this case
the remote scheduled task achieves lateral movement. 

Adversaries can create and configure scheduled tasks on remote endpoints 
using either the task scheduler or PowerShell.

One example syntax used to create a new task on a remote computer is to 
use \computername

Examples: 

at \\computername time/interactive | /every: date, ... /next: date, ... command
at \\computername id/delete | /delete /yes

Run a scheduled task on a remote mashine using PowerShell, example:

schtasks /run /s ComputerName /tn “description”

Using the task Scheduler, as example: > "Connect to Another Computer", 
provide the IP address of the remote system and select "Connect as another 
user" > "Set User".

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actor uses an already compromised Windows endpoint. Requires administrative 
credentials with permissions for remote task creation. Requires that
Windows firewall on the remote endpoint allows “Remote Scheduled Tasks 
Management”).

Domains: Enterprise, Public Cloud
Targets: Workstations, Control Server, Input/Output Server, Laptop, Desktop, Remote access, Web Application Servers, Public-Facing Servers
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement | Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery. |
| Leverage | Dwelling; Infrastructure Compromise; Modify configuration; Software installation | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1053` | [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) | Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)  Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process.(Citation: ProofPoint Serpent) |
| `T1053.005` | [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.(Citation: Stack Overflow) In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path.(Citation: Red Canary - Atomic Red Team)  An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)  Adversaries may also create "hidden" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments) |
