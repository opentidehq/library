# Windows explorer used to search for files with credentials

## Metadata

- **UUID**: `78d80d14-7260-44b8-95e9-6cf3693b0024`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Credential dumping is the process of extracting sensitive information, such
as passwords, normally in the form of a hash or a clear text content, as well
as any other secrets stored on the compromised host ref [1], [2].         

On Windows, the user's passwords and secrets can be stored in multiple
possible locations, accessible with Windows File Explorer.  

For example:

### Security Accounts Manager (SAM) database location

Location of the SAM database, contains the local users of the host as well
as the local groups: 

`%SystemRoot%/system32/config/SAM`

### Windows Security configuration file

Security config file contains LSA Secrets, for example DPAPI machine key,
account cleartext passwords for Windows services or scheduled tasks that
are configured on the host. Data Protection API (DPAPI) performs symmetric
encryption of asymmetric private keys and it's used by the operation system
to securely store passwords, encryption keys or any other type of sensitive
data ref [3], [4] and [5].        

`%SystemRoot%/system32/config/SECURITY`

### AppData local user folder

AppData in the local user folder contains cleartext passwords,
web browsers cookies and other cached browser data:  

`%SYSTEMDRIVE%\Users\<USERNAME>\AppData\Local\Microsoft\Vault\<GUID>`

### Other possible Windows explorer locations for browsing

Some other paths in Windows Explorer may contain password manager details,
for example KeePass Password Database or similar.  

Examples for paths in Windows Explorer (local locations or network shares):

- `C:\Users\Public\TempWorkingFiles\PGM\Documents\Keepass\`
- `C:\Users\vernada\AppData\Local\Microsoft\AppV\Client\Integration\{identifier_string}\Root`
- `C:\ProgramData\AppV\{identifier_string}\Root\KeePass.exe`
- `C:\Users\USERNAME\Downloads\EBSI credentials\`
- `E:\KeePass-db\`  

### Automated scripts

The threat actors are using automated scripts that can search for specific
file extentions in Windows Explorer that usually contain sensitive data as 
user and system credentials.  

#### Batch script to search for files by a name

Example:

```
@echo off
set /p search_term=Enter search term: 
for /f "delims=" %%a in ('dir /b /s *%search_term%*') do echo %%a
```

#### PowerShell script to search for files in Windows by content

Example:

```
$search_term = Read-Host "Enter search term"
Get-ChildItem -Path C:\ -Recurse | Select-String -Pattern $search_term
```

#### Known extentions for files (possible to be discovered via Windows Explorer)

Browsing through Windows Explorer, threat actors are usually looking for
file extentions of files which may contain user's credentials ref [6].  

Example for file extensions that may contain credentials:  

- Compressed (archive) files: .zip, .tar, .gz, .tgz, .rar, and others
- Java source files: .java
- Text files: .txt
- PDF documents: .pdf 
- Office file documents: .doc, .docx, .rtf, .xlsx, .pptx, .pps, .ppsm, .ppsx, .ppt
- Backup files: .bak, .old and others
- Archive files: .7z, .zip , .rar
- Database files: .kd , kdbx, mdb
- Configuration files: .config, .xml, .xsml, .xsl, .xsd, .xps, .sys
- Execution files: .exe, .cmd, .ps1
- Libraries: .dll
- Shell configuration files: .bashrc, .zshrc, .cshrc
- User AWS Folder .aws/credentials
- Other possible files that may contain credentials: csv, tmp, .ssh, .wxs

## Techniques
- T1003
- T1552.001
- T1005
- T1552
