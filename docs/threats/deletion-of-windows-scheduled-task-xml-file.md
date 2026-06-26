# Deletion of Windows Scheduled Task XML file

## Metadata

- **UUID**: `3c4d13c9-d40f-4f97-b8fa-607b6f7ad263`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
When a scheduled task is created, different artifacts related to the task
are generated and stored in a XML file. This XML file contains all of the
information about the task, including the name, triggers, actions, and
other settings. In the xml code in the section "Actions" is stored a path
to the running task, for example “C:\Windows\System32\task.exe”. Threat
actors may delete the corresponding XML file to a scheduled task to hide
their activities on the system. Threat actors can delete the XML file
manually from C:\Windows\System32\Tasks folder or by using CMD or other
CLId/shells, bash, or PowerShell scripts.

Example for deletion of XML file with bash commands:

cd /mnt/c/Windows/System32/Tasks
rm taskname.xml

Example for deletion of XML file with PowerShell commands:

cd C:\Windows\System32\Tasks
Remove-Item taskname.xml

In cloud infrastructures threat actors are using command-line interface
(CLI) like CloudShell in Azure. 

Example: 

Navigate to the path where the XML file is stored and delete the file with
the command "del":

cd C:\Windows\System32\Tasks
del taskname.xml

Deleting the XML file will only remove the task from the Task Scheduler.
It will not uninstall any programs or delete any files that were associated
with the task.

## Techniques
- T1053.005
- T1564
