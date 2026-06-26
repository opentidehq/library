# Cron manipulation

## Metadata

- **UUID**: `22c2fc38-93f5-41ee-be2d-a7737fa2b936`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Suspicious cron activity refers to the insertion or modification of scheduled tasks
(cron jobs) on Unix-like systems (including Linux and macOS) in order to achieve 
or maintain unauthorized persistence. This technique takes advantage of the legitimate 
cron scheduling service to run malicious commands at regular intervals.  

In practice, a threat actor will add a hidden or obfuscated entry to `/etc/crontab`, 
user-specific cron files (e.g., `/var/spool/cron/`), or 
system-wide cron directories (e.g., `/etc/cron.d/`). 
These hidden entries often execute scripts that download additional malware, 
exfiltrate data, or establish a persistent backdoor.

Some known threat actors has leveraged cron-based jobs to deploy cryptocurrency miners 
and move laterally within compromised environments, often targeting cloud-based 
or containerized setups. 
Attackers have also been identified using stealthy cron modifications to maintain 
a foothold on victim systems, execute remote commands, and ensure that malicious binaries 
are relaunched even after a reboot.

## Techniques
- T1053.003
