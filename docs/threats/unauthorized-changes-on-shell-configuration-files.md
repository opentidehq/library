# Unauthorized changes on shell configuration files

## Metadata

- **UUID**: `97589310-35d6-4e7d-a8b5-2d6cfc6375f4`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Attacker may change critical files on Unix-like systems,

* shell initialisation and configuration, such as:
  - `/etc/profile`, `/etc/shells`, `/etc/profile.d/*`, `/etc/bash.bashrc`, 
  `/etc/bashrc`, `/etc/zsh/zprofile`, `/etc/zsh/zshrc`, `/etc/zsh/zlogin`, 
  `/etc/zsh/zlogout`, `/etc/csh.cshrc`, `/etc/csh.login`,
* as well as root-owned configuration files, such as:
  * `/root/.bashrc`, `/root/.bash_profile`, `/root/.profile`, `/root/.zshrc`, 
  `/root/.zprofile`
* and user-specific files, such as:
  * `/home/*/.bashrc`, `/home/*/.zshrc`, `/home/*/.bash_profile`, 
  `/home/*/.zprofile`, `/home/*/.profile`, `/home/*/.bash_login`, 
  `/home/*/.bash_logout`, `/home/*/.zlogin`, `/home/*/.zlogout`

These files are typically executed whenever a user logs in or spawns a new 
shell session. By manipulating these files, attackers may:

1. **Introduce malicious code** by modifying the configuration files with 
the objective of dropping malware to the compromised system, such as 
Backdoors or Trojans.
2. **Alter system settings**: Changes to the configuration files can modify 
system settings, such as environment variables, PATH variables, or other 
critical settings, which can compromise the system's security and integrity.
3. **Disable security features** such as audit logging or access controls, 
to evade detection or gain unauthorized access to the system.
4. **Create unauthorized access**: Modifications to the configuration files 
can create unauthorized access points, such as adding new users or modifying 
existing user accounts.

## Techniques
- T1546.004
