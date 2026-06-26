# AppLocker bypass using writable folders

## Metadata

- **UUID**: `ff8c52ac-77d0-4bee-9f6d-e40fc6e0da63`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
AppLocker bypass using writable folders is a technique where an attacker
exploits the fact that AppLocker only checks the executable file's path,
not the path of the folder containing the executable. By placing a malicious
executable in a writable folder that is not restricted by AppLocker, an
attacker can bypass AppLocker controls.  

AppLocker uses a set of rules to determine which applications are allowed
to run. These rules are based on factors like the application's path,
publisher, and hash. If a threat actor can write to a folder that is allowed
by AppLocker, they can potentially bypass the restrictions.  

### Examples for AppLocker writable folders

The list below includes some of the folders in Windows where a standard user
have write permissions by default. These permissions can be used by threat
actors and let them to bypass AppLocker Windows whitelisting functionality.
For more information please check ref [1], [2].  

- `C:\Windows\Tasks` - Windows Tasks directory, writable by the "Users" group
- `C:\Windows\Temp`  - Temporary Files
- `C:\Windows\tracing`
- `C:\Windows\Registration\CRMLog`
- `C:\Windows\System32\FxsTmp`
- `C:\Windows\System32\com\dmp`
- `C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys`
- `C:\Windows\System32\spool\PRINTERS`
- `C:\Windows\System32\spool\SERVERS`
- `C:\Windows\System32\spool\drivers\color`
- `C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter`
- `C:\Windows\System32\Tasks_Migrated`
   (after peforming a version upgrade of Windows 10)
- `C:\Windows\SysWOW64\FxsTmp`
- `C:\Windows\SysWOW64\com\dmp`
- `C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter`
- `C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System`

Additional ref [3], [4]:

- `%APPDATA%`                        # Application Data / Roaming User Data
- `%LOCALAPPDATA%`                   # Local Application Data / Local User Data
- `%USERPROFILE%\Desktop`            # User's Desktop): Desktop
- `%USERPROFILE%\AppData\Local\Temp` # Local Low, this is a subfolder of %LOCALAPPDATA%

### Other possible writable folders in AppLocker

There are some other possible writable folders in `C:\WINDOWS` where a
standard Windows user may have write permissions by default. For example,
'accesschk.exe' from Sysinternals Suite can be used to find folders that
are writable and can be leveraged. Furthermore, 'icacls.exe' can be used to
determine if we also have execute rights within the targeted folder.

Different threat actors are actively exploiting this AppLocker bypass
technique to deploy malware, execute malicious code, and gain persistence
on compromised systems.

### Example

Lenovo devices include a file, MFGSTAT.zip, in C:\\Windows that is writable
by authenticated users. An attacker can embed a malicious payload into an
NTFS alternate data stream within this ZIP file and invoke it via a signed
Windows binary (e.g., AppVLP.exe), bypassing AppLocker rules.

## Techniques
- T1218
