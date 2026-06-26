# Credential file download to compromised Windows endpoint

## Metadata

- **UUID**: `94b7287b-ae84-4b89-8093-63898c7475c9`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A credential file download to Windows compromised endpoint
refers to a process where an attacker downloads sensitive
credential files to this system. A threat actor usually
target to download files containing passwords, authentication
tokens, or other sensitive information. Threat actors may use
remote tools to download Windows credential files and to
extract their content if its decrypted ref [1], [2].  

### Methods used by the threat actors

Threat actors may use various methods to download credential files,
for example:

- SMB (Server Message Block) exploitation: Attackers may exploit
vulnerabilities in SMB to gain access to the compromised endpoint
and download credential files.
- PowerShell scripts: Attackers may use PowerShell scripts to
download credential files from the compromised endpoint.
- Remote Desktop Protocol (RDP): Attackers may use RDP to gain
access to the compromised endpoint and download credential files.
- Malware: Attackers may use malware to download credential files
from the compromised endpoint.
- Curl for Windows (via HTTP requests) - Adversaries could abuse
`Curl` to download files or upload data to a remote URL address
ref [2].  
- Remote Desktop PassView - this tool can access Windows credential
files via .rdp files. It's possible such file to contain user's
credentials ref [3]. 

### Known types of files which may contain user's credentials 

The following types of credential files may be downloaded by the
attackers through a compromised network:

- SAM (Security Account Manager) files: These files contain hashed
passwords for local user accounts.
- NTDS.DIT files: These files contain hashed passwords for Active
Directory user accounts.
- Credential Manager files: These files contain stored credentials
for applications and services.
- SSH key files: These files contain private SSH keys used for
authentication.  

### An example 

Threat actors can download and use the accessed credential user's
files to connect to a database further, without having to enter
login credentials each time they access the database. The database
system will authenticate their login based on the information
stored in the credential file.

## Techniques
- T1552.001
- T1555.004
