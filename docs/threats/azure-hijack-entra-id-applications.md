# Azure - Hijack Entra ID Applications

## Metadata

- **UUID**: `78d5e363-14db-40c0-a1c4-4ba02a3e60d4`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Hijacking an application (by adding a rogue secret or certificate) with granted permissions 
will allow the attacker to access data that is normally protected by MFA requirements.
Modification of an application via the browser - The attacker connected to the 
Azure Portal with a web browser and added a new secret to an App Registration that
had permissions to read all mail. There is no supported way to add a credential 
to an Enterprise Application (service principal) via the browser.
Modification of an application via PowerShell - The attacker connected to the Microsoft 
365 tenant using Azure AD PowerShell. Once connected they added certificates to App 
Registrations and Enterprise Applications that had the mail.read and files.read permission.

## Techniques
- T1114
- T1114.002
- T1098.001
