# OneDrive API abuse to exfiltrate sensitive data

## Metadata

- **UUID**: `10663f4a-6432-4c8f-bd3a-eaa599bb474e`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
OneDrive API abuse to exfiltrate sensitive data occurs when attackers misuse legitimate 
Microsoft Graph API endpoints and OneDrive’s cloud storage features to steal confidential 
or sensitive information from an organization.

### How Does It Work?

1. **API Exploitation via Microsoft Graph**
  - Attackers use the Microsoft Graph API to access users’ OneDrive storage.
  - Common endpoints include:
    - `https://graph.microsoft.com/v1.0/users/{id}/drive` (to list drives)
    - `https://graph.microsoft.com/v1.0/drive/items/{item-id}/content` (to download files)
  - These APIs are normally used for legitimate cloud storage operations.

2. **OAuth and Application Permissions**
  - Attackers may compromise existing OAuth applications or create new ones.
  - By granting these applications broad permissions (like “Files.Read.All” or 
  “Files.ReadWrite.All”), attackers gain access to OneDrive files without direct 
  user interaction.

3. **Use of Trusted Cloud Services**
  - Data exfiltration is carried out through OneDrive, a trusted and widely used 
  cloud service.
  - This makes malicious activity harder to distinguish from normal business operations.

4. **Automated Exfiltration**
  - Attackers often use scripts or malware to automate the process of accessing 
  and transferring files via OneDrive.
  - This allows for large-scale, stealthy data theft.

### Attack Scenarios

- **Compromised Credentials:** An attacker gains access to an account with OneDrive 
API permissions.
- **Malicious OAuth App:** An attacker registers an OAuth app with excessive permissions 
and uses it to access OneDrive files.
- **Automated Scripts:** Attackers use PowerShell or other scripting tools to interact 
with the OneDrive API, extracting sensitive files at scale.

## Techniques
- T1190
- T1534
