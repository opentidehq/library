# Scheduled tasks created with command line

## Metadata

- **UUID**: `2b560980-d4c6-428c-963f-697e7e29938c`
- **Schema**: `threat::1.0`
- **TLP**: clear

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

## Techniques
- T1053.005
