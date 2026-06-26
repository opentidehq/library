# Automation accounts JWT extraction

## Metadata

- **UUID**: `841e2a63-c95f-43f8-aef0-7ab96456445a`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
The threat vector refers to attacks where attackers exploit Azure Automation Accounts 
to steal JSON Web Tokens (JWTs) associated with Managed Identities, enabling privilege 
escalation and lateral movement in cloud environments. Here's a detailed breakdown:

## Attack Methodology
**JWT Extraction via Runbook Modification**  
Attackers modify Automation Account runbooks to execute PowerShell scripts that 
access the Managed Identity endpoint:  
```powershell
$tokenAuthURI = $env:MSI_ENDPOINT + "?resource=https://graph.microsoft.com/&api-version=2017-09-01"
$tokenResponse = Invive-RestMethod -Method Get -Headers @{"Secret"="$env:MSI_SECRET"} -Uri $tokenAuthURI
$tokenResponse.access_token
```
This script retrieves a JWT for the Automation Account's Service Principal, which 
attackers then exfiltrate.

## Abuse Potential
- **Privilege Escalation**: Stolen JWTs grant the same permissions as the Automation 
Account's Managed Identity, enabling access to Azure Graph API, Key Vaults, and 
other services.
- **Token Replay**: Attackers use extracted JWTs to authenticate as the Service 
Principal outside Azure Automation's context.
- **Algorithm Confusion**: Weak JWT validation could allow attackers to modify token 
claims while maintaining valid signatures (e.g., switching from RS256 to HS256).

## Tooling
- **JWTXposer**: Scans archives for leaked JWTs and analyzes claims for privilege 
escalation opportunities.
- **jwt_tool**: Performs dictionary attacks against JWT secrets and exploits algorithm 
confusion vulnerabilities.
- **Azure APIs**: Native tools like Az PowerShell modules can abuse valid JWTs for 
resource enumeration.

## Techniques
- T1134
- T1528
- T1550.001
- T1190
