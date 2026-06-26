# Listing passwords stored in registry

## Metadata

- **UUID**: `0834302b-90d3-45ec-95d1-3e41ec14f7c6`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Listing passwords stored in the Windows Registry is a technique employed by adversaries 
to extract sensitive credentials from compromised systems. The Windows Registry is a 
centralized database that stores configuration settings and options for the operating 
system and installed applications. Some applications, due to misconfigurations or poor 
security practices, store user credentials in the registry, sometimes in plaintext 
or in an easily reversible format.  

Threat actors may use the built-in Windows command-line utility reg.exe to query registry 
keys that potentially contain stored credentials.  

```bat
reg query HKLM /f password /t REG_SZ /s
```
This command is scanning registry hives for the value password.  

PowerShell provides a powerful scripting environment that can recursively search the 
registry for keys containing specific terms like "password."  

```powershell
Get-ChildItem -Path Registry:: -Recurse -ErrorAction SilentlyContinue |
Get-ItemProperty |
Where-Object { $_.PSObject.Properties.Name -match "Password" -and $_.Password }
```
This script searches all registry keys for properties named "Password" and lists them if found.  

Some applications store credentials in specific registry locations. For example, 
VPN clients or database tools might store user credentials under their software keys in HKCU or HKLM hives.

## Techniques
- T1552.002
