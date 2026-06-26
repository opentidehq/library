# Local user account added

## Metadata

- **UUID**: `e2d8ce6b-f21e-4444-a828-0c6b722a9c93`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors may add or modify local user accounts on compromised systems to 
establish persistence, maintain unauthorized access, and potentially 
escalate privileges. By leveraging administrative permissions—often obtained 
through credential theft, exploitation of vulnerabilities, or lateral movement—
adversaries create new user accounts that allow them to re-enter the system 
at will, even if initial malware implants or other backdoor mechanisms 
are detected and removed.  

## Windows

Adversaries might run commands like :
```bash
net user /add [username] [password] 
or 
net localgroup administrators [username] /add
```

To stealthily provision accounts with elevated permissions. 

## Linux or macOS

Threat actors may modify :
```bash
/etc/passwd
or 
/etc/shadow
``` 
or use commands like `useradd` or `dscl` to create new users.
The changes perfomed by using the above commands can be detected by 
monitoring certain paths, such as `/usr/sbin/useradd`.  
In some cases, attackers may script these actions to occur automatically during 
their post-exploitation phase, making detection more challenging.  

In practice, once these local accounts are established, the attackers can 
maintain a foothold within the environment, pivot to other hosts, 
exfiltrate data, or stage further attacks. The long-term impact of such 
account additions may lead to data breaches, reputation damage, financial 
loss and regulatory consequences.

## Techniques
- T1136.001
