# Disabling of Windows event logging through registry entries

## Metadata

- **UUID**: `dbbeb66b-cb18-4055-8af4-808a8efdc748`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors can disable Windows event logs by adding, deleting or modifying
registry entries manually or with commands in a command-line prompt. 

The threat actor may disable the Windows Event log events manually via
Event Viewer properties or with CLI commands to disable a specific event or
all of them. Threat actors may also use script files or PowerShell to change
the registry.

If the threat actors want to disable event logging manually via registry
entries, they have to find the associated GUID to the event that will delete. The
GUID can be taken for example from Event Viewer > Select specific event log
> Event Properties > in Details select "XML view". (example for GUID id:
Giud="{BD12F3B8-4DE1-TR31-DE39RET84L12}") After this the threat actor
navigates to the registry with the GUID that needs to delete and change
the value of the dword in the registry key "Enabled" to 0.

Example: 

1. Example for disabling the logging of all event logs via registry entry:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog" /v Start /t REG_DWORD /d 4 /f

2. Example for disabling the logging of a specific event log via registry entry:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog[Log Name]" /v TypesSupported /t REG_DWORD /d 0 /f

3. Manual change in the registry of the registry key "Enable" (dword value) to 0. 
  
  Registry: 
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System

  Dword value change in the registry key "Enable":

  "Enabled"=dword:0
  "EnableProperty"=dword:0

Example for change of Audit policies in the registries:

psexec -s -i regedit (the command needs system-level access to run)
After that in HKLM\SECURITY\Policy\PolAdtEv registry hive in the registry
editor "Edit Binary Value", 16-bit (two-byte) values can be changed to
00 00 which means no audit. For example replace the data started with 
01 00 01 00 to 00 00 00 00

- 00 00 means no auditing
- 01 00 means success auditing
- 02 00 means failure auditing
- 03 00 means all auditing

## Techniques
- T1562.002
