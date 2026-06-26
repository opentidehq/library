# Change file owner to a privileged account

## Metadata

- **UUID**: `682bf600-ec3e-4780-9f8f-8305ac602bef`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries seeking to gain or maintain elevated privileges often target the 
ownership and permissions of critical files or directories. By changing a 
file’s owner to a privileged account (e.g., SYSTEM on Windows, `root` on Linux, 
or `root:wheel` on macOS), threat actors ensure that their malicious tools, 
binaries, or configuration files inherit elevated trust levels. 
This manipulation can facilitate various malicious objectives, including 
executing code with higher privileges, bypassing security controls, 
and evading detection.  

### Windows

Attackers may use built-in utilities such as `takeown.exe` or `icacls.exe` 
to change ownership and grant Full Control permissions to a high-privilege 
user or group.  

For instance:  
```powershell
takeown.exe /f C:\sensitive_data.txt
icacls.exe C:\sensitive_data.txt /setowner Administrator
icacls.exe C:\sensitive_data.txt /grant Administrator:F
```

By doing so, they can ensure that subsequent manipulations of these files, 
including the addition of backdoors, data exfiltration tools, 
or credential-stealing binaries, are executed under a privileged context.  

### Linux and macOS

Threat actors mainly rely on the `chown` command to modify file ownership. 
But other commands may achieve the same objective like chgrp or setfacl 

For example:
```bash
sudo chown root:root /usr/local/bin/malicious_script
```

Once a file is owned by `root`, it can be paired with setuid bits 
or extended attributes, enabling the file to run with elevated privileges.

## Techniques
- T1222
