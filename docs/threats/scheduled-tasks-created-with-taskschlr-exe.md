# Scheduled tasks created with taskschlr.exe

## Metadata

- **UUID**: `24503678-9a1b-4af3-9837-a90bf47b7dda`
- **Schema**: `threat::1.0`
- **TLP**: clear

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

## Techniques
- T1053.005
