# Abuse of special permission via chmod on files

## Metadata

- **UUID**: `52cd3405-ddd8-40cd-be83-640a21c2b4c4`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Attackers leverage the `chmod` utility to set the SUID (Set Owner User ID), 
the SGID (Set Owner Group ID), or the Sticky bit on executables or scripts. 
By abusing these bits, an adversary can temporarily inherit root- 
or group-level privileges when the affected file is executed.  

This effectively grants them elevated rights that can be used to move laterally 
within the environment, access or exfiltrate sensitive data, or escalate 
privileges to maintain a stronger foothold on the system.  

Examples of SUID, SGID, and Sticky bit abuse:

SUID shell: Attackers can create a file with the setuid bit set and owned
by the root user, and then use that file to gain root privileges and 
execute a shell with root privileges.

SGID exploit: Attackers can find a file with the setgid bit set and owned
by a group that has elevated privileges, and then use that file to gain the
privileges of that group.

Sticky bit exploit: Attackers can set the sticky bit on a file to prevent
it from being deleted or renamed, and then use that file to store malicious
code or data.

In many Linux-based distributions (and similarly on macOS systems), 
`chmod` is widely available and not restricted in typical configurations. 
Attackers can take advantage of this by running commands such as:

```bash
chmod u+s /path/to/executable
```

or

```bash
chmod g+s /path/to/executable
```
Depending on permissions misconfigurations, these commands may succeed if the 
account in use has the necessary rights or if the system’s sudo settings 
are overly permissive.  

Once the SUID or SGID bit is set on a critical binary, any user running that 
binary subsequently executes it with elevated privileges. Threat actors have 
been observed employing this technique to gain root-level access, tamper with 
system logs, exfiltrate proprietary data, or introduce backdoors for persistence.

## Techniques
- T1548.001
