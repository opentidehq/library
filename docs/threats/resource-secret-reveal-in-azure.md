# Resource Secret Reveal in Azure

## Metadata

- **UUID**: `37381f28-ad9f-40c3-80f8-d8a82d6ce9a3`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-09-15`
- **Modified**: `2025-09-15`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://microsoft.github.io/Azure-Threat-Research-Matrix/CredentialAccess/AZT605/AZT605/](https://microsoft.github.io/Azure-Threat-Research-Matrix/CredentialAccess/AZT605/AZT605/)
- **2**: [https://learn.microsoft.com/en-us/azure/defender-for-cloud/secrets-scanning](https://learn.microsoft.com/en-us/azure/defender-for-cloud/secrets-scanning)

## Description
The following threat vector involves adversaries accessing sensitive secrets, keys, 
or credentials stored or used by Azure resources such as KeyVaults, Storage Accounts, 
Automation Accounts, or within deployment histories.

### Example Attack Scenario

An attacker with sufficient privileged access in Azure exploits misconfigured permissions, 
allowing them to access a Storage Account and execute the `listkeys` action. This 
reveals access keys that grant full control over the account's data. Alternatively, 
by editing or viewing Azure Automation Account runbooks or Resource Group deployment 
history, the attacker discovers embedded credentials or secrets used in automation 
processes, which may then be used to escalate privileges or move laterally within 
the environment.

### Attack Goals and Impact

- **Primary goal:** Exfiltrate sensitive secrets, such as Storage Account access 
keys, service principal credentials, KeyVault secrets, or any plaintext credentials 
exposed in ARM templates or automation runbooks.
- **Impact:** Once these secrets are exposed, attackers can impersonate service 
identities, gain unauthorized access to data, break the integrity and confidentiality 
of cloud services, or launch further attacks including data exfiltration, lateral 
movement, persistence, or privilege escalation.

### Attack Flow and Methodology

- **Reconnaissance:** Identifies potential resources containing secrets, such as 
Storage Accounts, Automation Accounts, or deployment resource groups.
- **Execution:** 
    - For Storage Accounts: Executes `Microsoft.Storage/storageAccounts/listkeys/action` 
    to dump access keys.
    - For Automation Accounts: Edits or reviews runbooks to extract embedded credentials.
    - For Resource Groups: Reads deployment history to extract secrets/credentials 
    embedded in ARM templates.
- **Objective:** Uses the exfiltrated secrets to access additional resources, escalate 
privileges, or maintain persistence in the Azure environment.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries obtains sufficient privileges (via phishing,
misconfigurations, lateral movement, or exploitation of
weak access controls).

Domains: Public Cloud
Targets: Key Store, Cloud Storage Accounts
Platforms: Azure, Azure AD**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | IP Loss; Reputational Damages; Identity Theft; Business disruption | - |
| Leverage | Information Disclosure; Elevation of privilege; Modify privileges | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1552` | [Unsecured Credentials](https://attack.mitre.org/techniques/T1552) | Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)),  or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).(Citation: Brining MimiKatz to Unix) |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |
| `T1555` | [Credentials from Password Stores](https://attack.mitre.org/techniques/T1555) | Adversaries may search for common password storage locations to obtain user credentials.(Citation: F-Secure The Dukes) Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information. |

## Chaining
```mermaid
flowchart LR
37381f28_ad9f_40c3_80f8_d8a82d6ce9a3["Resource Secret Reveal in Azure"]
b1593e0b_1b3b_462d_9ab6_21d1c136469d["Azure - Gather Resource Data"]
53f4e2f0_7d11_4629_bb26_905993a589db["Azure - Storage account reconnaissance"]
2743bf18_3b86_4721_bf3e_153dcda0b149["Azure - Valid Credentials"]
81338b90_f80c_40cc_8a57_ba97cdf86948["Azure - Key Vault reconnaissance"]
bcf3bb96_ed97_4853_98ab_937c2d214f4e["Azure - Key Vault persistence"]
37381f28_ad9f_40c3_80f8_d8a82d6ce9a3 -->|atomicity::implemented| b1593e0b_1b3b_462d_9ab6_21d1c136469d
b1593e0b_1b3b_462d_9ab6_21d1c136469d -->|atomicity::implemented| 53f4e2f0_7d11_4629_bb26_905993a589db
53f4e2f0_7d11_4629_bb26_905993a589db -->|support::enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|atomicity::implemented| 81338b90_f80c_40cc_8a57_ba97cdf86948
81338b90_f80c_40cc_8a57_ba97cdf86948 -->|support::synergize| bcf3bb96_ed97_4853_98ab_937c2d214f4e
```
### Chaining details
#### implemented -> Azure - Gather Resource Data (`atomicity::implemented`)
An adversary may obtain information and data within a resource.

- **Target UUID**: `b1593e0b-1b3b-462d-9ab6-21d1c136469d`
#### implemented -> Azure - Storage account reconnaissance (`atomicity::implemented`)
Adversaries need to scan and discover publicly accessible storage containers by 
guessing or enumerating storage account and container names.

- **Target UUID**: `53f4e2f0-7d11-4629-bb26-905993a589db`
#### enabled -> Azure - Valid Credentials (`support::enabled`)
Adversaries obtain the username and password of an AzureAD user either through phishing, 
password spraying, brute-force attacks, or credentials leaked online.

- **Target UUID**: `2743bf18-3b86-4721-bf3e-153dcda0b149`
#### implemented -> Azure - Key Vault reconnaissance (`atomicity::implemented`)
Adversaries must first compromise user accounts, service principals, or managed 
identities that already possess some level of Azure access.

- **Target UUID**: `81338b90-f80c-40cc-8a57-ba97cdf86948`
#### synergize -> Azure - Key Vault persistence (`support::synergize`)
Adversaries must first gain access to an Azure environment, typically through compromised 
user accounts, service principals, or managed identities.

- **Target UUID**: `bcf3bb96-ed97-4853-98ab-937c2d214f4e`
