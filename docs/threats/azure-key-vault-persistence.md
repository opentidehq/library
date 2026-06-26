# Azure - Key Vault persistence

## Metadata

- **UUID**: `bcf3bb96-ed97-4853-98ab-937c2d214f4e`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2025-06-12`
- **Modified**: `2025-09-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/](https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/)
- **2**: [https://nhimg.org/secrets-exposure-via-azure-key-vault-role](https://nhimg.org/secrets-exposure-via-azure-key-vault-role)
- **3**: [https://learn.microsoft.com/en-us/azure/key-vault/general/overview](https://learn.microsoft.com/en-us/azure/key-vault/general/overview)

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

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries must first gain access to an Azure environment, typically through compromised 
user accounts, service principals, or managed identities.

Domains: Public Cloud, Enterprise, Private Cloud
Targets: Cloud Storage Accounts, Key Store, Identity Services, Public-Facing Servers, API Endpoints, Cloud Portal, Serverless, Virtual Machines, IaaS
Platforms: Azure AD**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Monetary Loss; Lose Capabilities; Business disruption | - |
| Leverage | Spoofing; Tampering; Elevation of privilege; Information Disclosure; Modify configuration; Modify privileges; Modify data | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1098.001` | [Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) | Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.  For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID.(Citation: Microsoft SolarWinds Customer Guidance)(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) These credentials include both x509 keys and passwords.(Citation: Microsoft SolarWinds Customer Guidance) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules.(Citation: Demystifying Azure AD Service Principals)  In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys using either the <code>CreateKeyPair</code> or <code>ImportKeyPair</code> API in AWS or the <code>gcloud compute os-login ssh-keys add</code> command in GCP.(Citation: GCP SSH Key Add) This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts.(Citation: Expel IO Evil in AWS)(Citation: Expel Behind the Scenes)  Adversaries may also use the <code>CreateAccessKey</code> API in AWS or the <code>gcloud iam service-accounts keys create</code> command in GCP to add access keys to an account. Alternatively, they may use the <code>CreateLoginProfile</code> API in AWS to add a password that can be used to log into the AWS Management Console for [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538).(Citation: Permiso Scattered Spider 2023)(Citation: Lacework AI Resource Hijacking 2024) If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)).(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Sysdig ScarletEel 2.0) For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator.(Citation: SpecterOps Azure Privilege Escalation)   In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to [Forge Web Credentials](https://attack.mitre.org/techniques/T1606) tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated. (Citation: Crowdstrike AWS User Federation Persistence)  In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account.(Citation: Mandiant APT42 Operations 2024) As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.(Citation: Microsoft Entra ID App Passwords) |
| `T1548` | [Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548) | Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk.(Citation: TechNet How UAC Works)(Citation: sudo man page 2018) An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.(Citation: OSX Keydnap malware)(Citation: Fortinet Fareit) |
| `T1555.006` | [Credentials from Password Stores: Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006) | Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault.    Secrets managers support the secure centralized management of passwords, API keys, and other credential material. Where secrets managers are in use, cloud services can dynamically acquire credentials via API requests rather than accessing secrets insecurely stored in plain text files or environment variables.    If an adversary is able to gain sufficient privileges in a cloud environment – for example, by obtaining the credentials of high-privileged [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) or compromising a service that has permission to retrieve secrets – they may be able to request secrets from the secrets manager. This can be accomplished via commands such as `get-secret-value` in AWS, `gcloud secrets describe` in GCP, and `az key vault secret show` in Azure.(Citation: Permiso Scattered Spider 2023)(Citation: Sysdig ScarletEel 2.0 2023)(Citation: AWS Secrets Manager)(Citation: Google Cloud Secrets)(Citation: Microsoft Azure Key Vault)  **Note:** this technique is distinct from [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005) in that the credentials are being directly requested from the cloud secrets manager, rather than through the medium of the instance metadata API. |
