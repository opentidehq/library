# Windows Explorer Manipulation via Registry Modification

## Metadata

- **UUID**: `8e5c12f1-cd48-417c-a9c9-883212bf98b6`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Explorer behaviour can be twisted by editing the registry keys
listed below. Changes act instantly, leave few artefacts, and
are often missed by file-centric defenses.

### Policy Edits Disable User Defenses
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer  
Setting `DisableTaskMgr`, `DisableRegistryTools`, `NoViewOnDrive` or
NoFind stops Task Manager, Regedit, search and drive browsing,
blinding users.
Setting `NavPaneShowAllFolders` or `NavPaneExpandToCurrentFolder` can 
modify the navigation pane.
When set to 0, this value hides certain folders in the navigation pane, 
such as system folders or folders that are not typically displayed,
making it difficult for users to detect malicious activity.
When set to 1, this value shows all folders in the navigation pane, 
including hidden and system folders, making it harder for users to 
distinguish between legitimate and malicious files or folders.

### Advanced Flags Hide Artefacts
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  
Flipping Hidden, ShowSuperHidden or SuperHidden hides system
files and payloads, thwarting GUI-based hunting.

### User Shell Redirection
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders  
Replacing Desktop, Startup or Personal paths diverts files or
autoruns to attacker-controlled folders for theft or persistence.

### System-Wide Folder Hijack
- HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders  
System-level redirection funnels all users' documents and
shortcuts to rogue directories, enabling broad data capture.

### Global Advanced Flags Override
- HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  
Modifying the machine hive mirrors the HKCU tweaks but forces
hidden-file suppression and other changes on every profile.

### Environment Variable Hijack
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders  
Altering %APPDATA%, %TEMP% or %DESKTOP% variables tricks apps
into saving data or loading DLLs from malicious locations.

### Namespace Injection
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace  
Creating fake CLSID subkeys inserts rogue folders in Explorer,
luring users to launch payloads masked as system objects.

### Drive AutoRun Seeds
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2    
Inserting AutoRun and command entries forces code execution
whenever a specific USB or network share is browsed.

### Default Shell Replacement
- HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell  
Repointing the Shell value swaps explorer.exe for a malicious
binary, gaining control each time a user signs in.

### Enabling AutoPlay for Malicious Devices
- HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers  
Changing the `DeviceType` or `Handler` settings can enable AutoPlay for specific 
devices, such as network shares, potentially executing malicious code.

## Techniques
- T1112
- T1547.001
