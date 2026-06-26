# Deletion of Tasks or Tree registry keys in scheduled task hives

## Metadata

- **UUID**: `d2ca077d-6ec6-4442-bdc5-b1822e9f4ae8`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors are using deletion of tree registry keys to remove
information related to their activities, for example created previously
scheduled tasks. For the deletion of tree registry keys, the threat actors
are using reg command in command-line utility with a parameter delete,
PowerShell commands or scripts or manually delete the registry keys from
Registry Editor (regedit). In Azure cloud infrastructure threat actors use
Azure CloudShell to delete registry keys.

Example for registry keys created upon creation of a new scheduled task:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\TASK_NAME
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}

The registy keys above can be deleted using the "reg delete" command. The 
"reg delete" command deletes the specified registry key and all of its 
subkeys.

reg delete "HKEY_LOCAL_MACHINE\Registry_Key" /f

Examples for deleting registry keys with PowerShell commands:

Remove-Item -Path HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\TASK_NAME -Force -Verbose

or

Get-Item Remove-Item -Path HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\TASK_NAME | Remove-Item -Force -Verbose

Where Get-Item command retrieves the Key name and then Remove-Item uses the
result from Get and deletes the key registry.

To delete registry keys using Azure CloudShell threat actors are using
Remove-ItemProperty cmdlet in Windows PowerShell or the rm command in Bash.

Examples:

Remove-ItemProperty -Path "HKLM:\Software\MyKey" -Name "MyValue"

rm "HKLM:\Software\MyKey"

## Techniques
- T1053.005
- T1564
