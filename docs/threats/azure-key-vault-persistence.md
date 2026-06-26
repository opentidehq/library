# Azure - Key Vault persistence

## Metadata

- **UUID**: `bcf3bb96-ed97-4853-98ab-937c2d214f4e`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Key Vault persistence refers to techniques attackers use to maintain ongoing, unauthorized 
access to Azure Key Vault and its contents—such as secrets, keys, and certificates—after 
initial compromise or detection. This persistence is typically achieved by modifying 
Key Vault access policies to grant permissions to additional malicious accounts 
or identities.

## How persistence is achieved

- **Access policy modification:**  
  - Attackers with sufficient permissions (such as `Microsoft.KeyVault/vaults/write` 
  or `Microsoft.KeyVault/vaults/accessPolicies/write`) can add their own user account 
  or a service principal to the Key Vault's access policy.
  - This allows the attacker to maintain access even if their original account is 
  disabled or monitored.
- **Privilege escalation:**  
  - Misconfigured roles, such as the "Key Vault Contributor" role, can be exploited 
  to grant data access rights, despite the role's intended purpose being limited 
  to management of the Key Vault resource itself.
  - This is possible because the role includes permissions to modify access policies, 
  enabling self-granting of data plane access.

## Attack scenarios

- **Initial access:**  
  - An attacker gains access to an account with Key Vault management permissions, 
  often via phishing or credential theft.
- **Privilege Escalation:**  
  - The attacker uses their permissions to modify Key Vault access policies, granting 
  themselves (or a controlled account) permissions to read, list, or decrypt secrets, 
  keys, and certificates.
- **Persistence:**  
  - The attacker adds additional malicious accounts or service principals to the 
  access policy, ensuring continued access even if their original account is blocked.
- **Data exfiltration and abuse:**  
  - With persistent access, the attacker can periodically extract secrets, keys, 
  or certificates, and use these to compromise other cloud workloads, disrupt operations, 
  or abuse services.

## Real-world risks

- **Data exposure:**  
  - Unauthorized access to secrets (e.g., API keys, connection strings, tokens) 
  can lead to broader system compromise.
- **Compromised credentials:**  
  - Stolen secrets can be used to access other Azure resources or external systems.
- **Stealthy Persistence:**  
  - Attackers can maintain long-term access, making detection and recovery difficult.
- **Service disruption and abuse:**  
  - Attackers may alter configurations, disrupt services, or deploy unauthorized 
  resources using stolen credentials.

## Techniques
- T1098.001
- T1548
- T1555.006
