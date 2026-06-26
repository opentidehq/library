# Scheduled tasks created with taskschlr.exe

## Metadata

- **UUID**: `24503678-9a1b-4af3-9837-a90bf47b7dda`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2022-12-12`
- **Modified**: `2022-12-13`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.thecodebuzz.com/schedule-run-exe-console-application-windows-task-scheduler/](https://www.thecodebuzz.com/schedule-run-exe-console-application-windows-task-scheduler/)
- **2**: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
- **3**: [https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler)
- **4**: [https://www.windowscentral.com/how-create-automated-task-using-task-scheduler-windows-10](https://www.windowscentral.com/how-create-automated-task-using-task-scheduler-windows-10)
- **5**: [https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)
- **6**: [https://redcanary.com/threat-detection-report/techniques/windows-command-shell/](https://redcanary.com/threat-detection-report/techniques/windows-command-shell/)

## Description
A threat actor can use the Task Scheduler to create tasks for nefarious purposes. For example, during 
the creation of a task in Task Scheduler > Create Task, the newly created task can be configured with 
specific options in the tab "Action". Through the "Action" settings the threat actor can specify 
the actions for the task to execute, which often include outbound connections to attacker 
infrastructure, binary execution or registry entry editing or creation.

Example: 

Action: "Start a program"
In Program/script field: C:\ProgramData\<name.exe>

Tasks are stored in C:\Windows\System32\Tasks\ in XML format.

They reside in the following registry:

HKLM\Software\Microsoft\Windows\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}

“Actions” value stored within the Tasks\{GUID} key points to the command line associated with the task.
In the registry under HKLM\Software\Microsoft\Windows\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}
there is a registry key for the task with a key "Actions" related to Tasks\{GUID} id. In "Edit Binary Value"
of the registy key "Action" there is a reference to the path which can contain malicious executable file,
for example: C:\Windows\System32\taskschlr.exe or other.

Similar information is stored within an extensionless XML file, created within C:\Windows\System32\Tasks, 
where the name of the file matches the name of the task. 

Example for Settings section in XML file with potentially malicious executable file: 

<Task version="the_version" xmlns="http_link">
 ...
 </Settings>
 <Actions Context="Author">
   <Exec>
    <Command>C\Windows\System32\taskschlr.exe</Command>
   </Exec>
 <Actions>
</Task>

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **An adversary has gained control over a Windows endpoint and has  
privileges to create scheduled tasks using taskschlr.exe

Domains: Enterprise
Targets: Workstations, Control Server, Input/Output Server, Laptop, Desktop, Remote access, Web Application Servers, Public-Facing Servers
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Business disruption; Impairement; Lose Capabilities | - |
| Leverage | Dwelling; Infrastructure Compromise; Elevation of privilege | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Execution | Techniques that result in execution of attacker-controlled code on a local or remote system. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] HAFNIUM](https://attack.mitre.org/groups/G0125) | `att&ck::G0125` | ('att&ck',) | [HAFNIUM](https://attack.mitre.org/groups/G0125) is a likely state-sponsored cyber espionage group operating out of China that has been active since at least January 2021. [HAFNIUM](https://attack.mitre.org/groups/G0125) primarily targets entities in the US across a number of industry sectors, including infectious disease researchers, law firms, higher education institutions, defense contractors, policy think tanks, and NGOs. [HAFNIUM](https://attack.mitre.org/groups/G0125) has targeted remote management tools and cloud software for intial access and has demonstrated an ability to quickly operationalize exploits for identified vulnerabilities in edge devices.(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)(Citation: Microsoft Silk Typhoon MAR 2025) |
| HAFNIUM | `misp::4f05d6c1-3fc1-4567-91cd-dd4637cc38b5` | ('misp',) | HAFNIUM primarily targets entities in the United States across a number of industry sectors, including infectious disease researchers, law firms, higher education institutions, defense contractors, policy think tanks, and NGOs. Microsoft Threat Intelligence Center (MSTIC) attributes this campaign with high confidence to HAFNIUM, a group assessed to be state-sponsored and operating out of China, based on observed victimology, tactics and procedures. HAFNIUM has previously compromised victims by exploiting vulnerabilities in internet-facing servers, and has used legitimate open-source frameworks, like Covenant, for command and control. Once they’ve gained access to a victim network, HAFNIUM typically exfiltrates data to file sharing sites like MEGA.In campaigns unrelated to these vulnerabilities, Microsoft has observed HAFNIUM interacting with victim Office 365 tenants. While they are often unsuccessful in compromising customer accounts, this reconnaissance activity helps the adversary identify more details about their targets’ environments. HAFNIUM operates primarily from leased virtual private servers (VPS) in the United States. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1053.005` | [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.(Citation: Stack Overflow) In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path.(Citation: Red Canary - Atomic Red Team)  An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)  Adversaries may also create "hidden" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments) |
