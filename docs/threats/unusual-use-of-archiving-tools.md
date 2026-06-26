# Unusual use of archiving tools

## Metadata

- **UUID**: `a1e8f8b3-48ef-4559-a3a0-ecaed496d5f3`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors often use legitimate archiving tools, like 7-Zip, WinRAR or tar, 
to compress and exfiltrate data from compromised systems. Attackers rename 
these executables or use the executables in ways that are atypical to evade 
security measures that would normally rely on standard file names 
or typical usage patterns.

Example : an attacker renaming 7z.exe to system32.exe and saving it in a
directory that is abnormal. They can then run the following command:
C:\Users\Public\system32.exe a -tzip C:\Users\Public\archive.zip C:\SensitiveData\*

This technique enables the attacker to archive sensitive data in a manner 
that would make the activity seem benign. The unusual locations of archive file 
creation and the usage of archiving tools with non-standard naming are 
the indicators of potentially malicious activity.

Also, a significant number of data compression and unusual outbound network traffic 
may indicate attempts to exfiltrate data.

## Techniques
- T1036
- T1027
- T1070
