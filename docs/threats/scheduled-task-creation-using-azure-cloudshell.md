# Scheduled task creation using Azure CloudShell

## Metadata

- **UUID**: `670504aa-cfb8-4d1f-a5ad-16193822085f`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors can use Azure CloudShell, which is accessible via the Azure
portal or the browser, to create scheduled tasks.

The path to the Action parameter of the scheduled task is set in the task.
Threat actors can also use the Azure CloudShell editor to edit and
visualize in a better format their code before deploying it.

For example, threat actors use "New-ScheduledTaskTrigger" cmdlet to create
a trigger for the new scheduled task and further "New-ScheduledTaskAction"
cmdlet to create a specific action for the task. In the end the 
"Register-ScheduledTask" cmdlet is used to create the scheduled task. 

$Trigger = New-ScheduledTaskTrigger -Daily -At <time: hh:mm>
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\My_task_script.ps1"
Register-ScheduledTask -TaskName "My Task" -Trigger $Trigger -Action $Action -RunLevel Highest

## Techniques
- T1053.005
