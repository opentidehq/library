# Scheduled tasks created with command line

## Metadata

- **UUID**: `2b560980-d4c6-428c-963f-697e7e29938c`
- **Schema**: `threat::1.0`
- **Version**: `4`
- **Created**: `2022-12-09`
- **Modified**: `2022-12-13`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://redcanary.com/threat-detection-report/techniques/scheduled-task/](https://redcanary.com/threat-detection-report/techniques/scheduled-task/)
- **2**: [https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/use-at-command-to-schedule-tasks](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/use-at-command-to-schedule-tasks)
- **3**: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
- **4**: [https://attack.mitre.org/software/S0111/](https://attack.mitre.org/software/S0111/)
- **5**: [https://redcanary.com/threat-detection-report/techniques/windows-command-shell/](https://redcanary.com/threat-detection-report/techniques/windows-command-shell/)
- **6**: [https://www.windowscentral.com/how-create-task-using-task-scheduler-command-prompt](https://www.windowscentral.com/how-create-task-using-task-scheduler-command-prompt)

## Description
Adversaries can use  Windows Command Shell (cmd.exe) to execute specific commands 
to create scheduled tasks for the purposes of dwelling, execution of binaries, 
or for communication to Command and Control server infrastructure.


Examples for creation of a scheduled task via command-line interface:

1. Create a daily task to run at specific time:

   SCHTASKS /CREATE /SC DAILY /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM

The folder path before the task name, under the /TN option, is not a requirement, 
but it'll help to keep the tasks separated. If the path is not specified, the task 
will be created inside the Task Scheduler Library folder.

2. Create a weekly task to run at specific time:

  SCHTASKS /CREATE /SC WEEKLY /D SUN /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM

3. Create monthly task to run at specific time:

  SCHTASKS /CREATE /SC MONTHLY /D 15 /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM

4. Create a scheduled task that runs daily as a specific user:

  SCHTASKS /CREATE /SC DAILY /TN "FOLDERPATH\TASKNAME" /TR "C:\SOURCE\FOLDER\APP-OR-SCRIPT" /ST HH:MM

Parameters that can be used in creation scheduled task command:

 /CREATE - specifies the creation a new automated routine task
 /SC - define the schedule of the task, for example it can include
 MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE, and ONEVENT.
 /D — specifies the day of the week to execute the task. (examples MON, TUE and etc)
 /TN — specifies the task name and location, the task can be created in a specific
 location directory (example /TN "FOLDERPATH\TASKNAME")
 /ST — defines the time to run the task (in 24 hours format)
 /RU — specifies the task to run under a specific user account.
 /QUERY — displays all the system tasks.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **An adversary has gained control over a Windows endpoint and has  
privileges to create scheduled tasks using the command line.

Domains: Enterprise, Public Cloud
Targets: Workstations, Control Server, Input/Output Server, Laptop, Desktop, Remote access, Web Application Servers, Public-Facing Servers
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement | Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery. |
| Leverage | Elevation of privilege; Infrastructure Compromise; Dwelling | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Execution | Techniques that result in execution of attacker-controlled code on a local or remote system. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] TA505](https://attack.mitre.org/groups/G0092) | `att&ck::G0092` | ('att&ck',) | [TA505](https://attack.mitre.org/groups/G0092) is a cyber criminal group that has been active since at least 2014. [TA505](https://attack.mitre.org/groups/G0092) is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaigns involving [Clop](https://attack.mitre.org/software/S0611).(Citation: Proofpoint TA505 Sep 2017)(Citation: Proofpoint TA505 June 2018)(Citation: Proofpoint TA505 Jan 2019)(Citation: NCC Group TA505)(Citation: Korean FSI TA505 2020) |
| TA505 | `misp::03c80674-35f8-4fe0-be2b-226ed0fcd69f` | ('misp',) | TA505, the name given by Proofpoint, has been in the cybercrime business for at least four years. This is the group behind the infamous Dridex banking trojan and Locky ransomware, delivered through malicious email campaigns via Necurs botnet. Other malware associated with TA505 include Philadelphia and GlobeImposter ransomware families. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1053.005` | [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.(Citation: Stack Overflow) In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path.(Citation: Red Canary - Atomic Red Team)  An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)  Adversaries may also create "hidden" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments) |
