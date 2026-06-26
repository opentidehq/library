# Windows credential dumping through Local Security Authority (LSA) Secrets

## Metadata

- **UUID**: `444e014f-d830-4d0d-9c2e-1f76d80ba380`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries may attempt to dump credentials to obtain account login
and credentials details, using techniques for Local Security Authority 
(LSA) Secrets dumping. If the attacker has a System access to the host 
this may lead to access LSA secrets database. Local Security Authority
contains credential information related to local and domain based accounts. 
The Registry is used to store the LSA secrets. When services are run under 
the context of local or domain users, their passwords are stored in the 
Registry at HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. If auto-logon is 
enabled, this information will be stored in the Registry as well. 
The extracted passwords are UTF-16 encoded, which means that they 
are returned in plaintext. LSA secrets can also be dumped from memory.

Known tools used for LSA credential dumping:

- pwdumpx.exe
- gsecdump
- Mimikatz
- secretsdump.py
- reg.exe (execution file extracts information from the Registry)
- Creddump7 (for gathering of credentials)

Executed commands and arguments that may access to a host may attempt to 
access Local Security Authority (LSA) secrets. Remote access tools may contain 
built-in features or incorporate existing tools like Mimikatz. PowerShell scripts
also can contain credential LSA dumping functionality.

## Techniques
- T1003
- T1003.004
