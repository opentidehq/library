# Azure - File Share Mounting

## Metadata

- **UUID**: `d24fcc84-0e1e-41e1-8d0e-6ee9f8c6a068`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-09-09`
- **Modified**: `2025-09-10`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://microsoft.github.io/Azure-Threat-Research-Matrix/Impact/AZT702/AZT702-1/](https://microsoft.github.io/Azure-Threat-Research-Matrix/Impact/AZT702/AZT702-1/)
- **2**: [https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/hunting-in-azure-subscriptions/4125875](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/hunting-in-azure-subscriptions/4125875)
- **3**: [https://www.microsoft.com/en-us/security/blog/2021/04/08/threat-matrix-for-storage/](https://www.microsoft.com/en-us/security/blog/2021/04/08/threat-matrix-for-storage/)
- **4**: [https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-azure-storage](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-azure-storage)

## Description
In the following threat vector, adversaries leverage Azure Storage Account File 
Shares via NFS or SMB mounts to facilitate or escalate attacks.

## Example Attack Scenario

A typical scenario begins with an attacker stealing or hijacking privileged credentials, 
for example through a “Pass the Cookie” attack on a global administrator account. 
After obtaining administrative access, the adversary extends permissions to external 
users and assigns them high-level roles within the Azure tenant. Leveraging this 
privileged access, the adversary mounts Azure file shares to their own infrastructure, 
laying the groundwork for:
- Massive data exfiltration through direct access to sensitive storage.
- Encrypting and holding file shares hostage for ransom (ransomware).
- Stealthily manipulating or deleting critical business data, including Azure backup sets.

## Attack Goals and Impact

The adversary’s core objectives when mounting file shares are:
- **Data Exfiltration:** Copying sensitive or proprietary data undetected from the 
cloud environment via NFS or SMB mount.
- **Ransomware Operations:** Encrypting contents of file shares directly, disrupting 
business continuity and demanding ransom payments for decryption.
- **Persistence and Shadow IT:** Creating redundant access paths or mirroring content 
to maintain long-term presence within the victim's environment.
- **Operational Disruption:** Deleting or corrupting critical files and backups 
to elevate operational risks and pressure response teams.

## Attack Flow and Methodology

The typical methodology for File Share Mounting attacks involves these steps:
- **Credential or Key Theft:** Adversaries obtain necessary Secrets, Shared Access 
Signatures (SAS), or access keys for a Storage Account, or elevate privileges to 
write and mount shares.
- **Generate/Enumerate Connection Strings:** Using their access, attackers create 
connection strings to Azure Storage File Shares, selecting NFS or SMB protocols 
as supported.
- **Mount File Shares:** The adversary mounts the target file shares to attacker-controlled 
machines or servers, treating Azure storage as a local/network drive.
- **Execute Objectives:** With direct file system access:
  - Download or exfiltrate data covertly.
  - Upload and execute ransomware, encrypt data, or sabotage backups.
  - Copy, modify, or delete content to facilitate further lateral movement or persistent threats.
- **Evasion:** These actions often evade Azure default audit logging, as connections 
to the mounted file shares are typically not logged within Azure's native monitoring 
tools by default, reducing detection opportunities.

## How the Adversary Generates the Connection String
The connection string typically contains the Storage Account name, File Share name,
and authentication tokens or keys (e.g., SAS tokens or storage account keys).

The attacker must have access to these authentication credentials, which can be 
obtained through compromise or misconfiguration.
With these credentials, the attacker constructs a connection string formatted like:

For SMB:
`\\<storage_account_name>.file.core.windows.net\<file_share_name>`
along with the storage account key or SAS token used for authentication.

For NFS:
A mount command such as
`mount -t nfs <storage_account_name>.file.core.windows.net:/<file_share_name> <local_mount_point>`.

Once mounted, the adversary can read, write, delete, or exfiltrate files directly from the 
file share as though it were a local drive.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries must steal Azure Storage Account keys, Shared Access Signatures (SAS), 
or Azure AD credentials that have permissions to access file shares. This could 
be through phishing, credential dumping, or leveraging misconfigurations

Domains: Public Cloud
Targets: Cloud Storage Accounts, Virtual Machines, Serverless, API Endpoints, Cloud Portal
Platforms: Azure, Azure AD, Windows, Linux, macOS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Lose Capabilities | - |
| Leverage | Spoofing; Tampering; Information Disclosure; Elevation of privilege; Modify configuration | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Impact | Techniques aimed at manipulating, interrupting or destroying the target system or data. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1039` | [Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039) | Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. |
| `T1530` | [Data from Cloud Storage](https://attack.mitre.org/techniques/T1530) | Adversaries may access data from cloud storage.  Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage. Similarly, SaaS enterprise platforms such as Office 365 and Google Workspace provide cloud-based document storage to users through services such as OneDrive and Google Drive, while SaaS application providers such as Slack, Confluence, Salesforce, and Dropbox may provide cloud storage solutions as a peripheral or primary use case of their platform.   In some cases, as with IaaS-based cloud storage, there exists no overarching application (such as SQL or Elasticsearch) with which to interact with the stored objects: instead, data from these solutions is retrieved directly though the [Cloud API](https://attack.mitre.org/techniques/T1059/009). In SaaS applications, adversaries may be able to collect this data directly from APIs or backend cloud storage objects, rather than through their front-end application or interface (i.e., [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)).   Adversaries may collect sensitive data from these cloud storage solutions. Providers typically offer security guides to help end users configure systems, though misconfigurations are a common problem.(Citation: Amazon S3 Security, 2019)(Citation: Microsoft Azure Storage Security, 2019)(Citation: Google Cloud Storage Best Practices, 2019) There have been numerous incidents where cloud storage has been improperly secured, typically by unintentionally allowing public access to unauthenticated users, overly-broad access by all users, or even access for any anonymous person outside the control of the Identity Access Management system without even needing basic user permissions.  This open access may expose various types of sensitive data, such as credit cards, personally identifiable information, or medical records.(Citation: Trend Micro S3 Exposed PII, 2017)(Citation: Wired Magecart S3 Buckets, 2019)(Citation: HIPAA Journal S3 Breach, 2017)(Citation: Rclone-mega-extortion_05_2021)  Adversaries may also obtain then abuse leaked credentials from source repositories, logs, or other means as a way to gain access to cloud storage objects. |
| `T1021.007` | [Remote Services: Cloud Services](https://attack.mitre.org/techniques/T1021/007) | Adversaries may log into accessible cloud services within a compromised environment using [Valid Accounts](https://attack.mitre.org/techniques/T1078) that are synchronized with or federated to on-premises user identities. The adversary may then perform management actions or access cloud-hosted resources as the logged-on user.   Many enterprises federate centrally managed user identities to cloud services, allowing users to login with their domain credentials in order to access the cloud control plane. Similarly, adversaries may connect to available cloud services through the web console or through the cloud command line interface (CLI) (e.g., [Cloud API](https://attack.mitre.org/techniques/T1059/009)), using commands such as <code>Connect-AZAccount</code> for Azure PowerShell, <code>Connect-MgGraph</code> for Microsoft Graph PowerShell, and <code>gcloud auth login</code> for the Google Cloud CLI.  In some cases, adversaries may be able to authenticate to these services via [Application Access Token](https://attack.mitre.org/techniques/T1550/001) instead of a username and password. |

## Chaining
```mermaid
flowchart LR
d24fcc84_0e1e_41e1_8d0e_6ee9f8c6a068["Azure - File Share Mounting"]
53f4e2f0_7d11_4629_bb26_905993a589db["Azure - Storage account reconnaissance"]
942ed69c_700a_469a_9591_07b87815a909["Azure - Storage Account Replication"]
b1593e0b_1b3b_462d_9ab6_21d1c136469d["Azure - Gather Resource Data"]
85c8e0dd_b012_402d_bb09_5d354c16ebb9["Azure - Local Resource Hijack"]
2743bf18_3b86_4721_bf3e_153dcda0b149["Azure - Valid Credentials"]
518ff777_f10d_4201_9e54_2779c31c512e["Consent phishing attack"]
d24fcc84_0e1e_41e1_8d0e_6ee9f8c6a068 -->|support::enabled| 53f4e2f0_7d11_4629_bb26_905993a589db
53f4e2f0_7d11_4629_bb26_905993a589db -->|support::synergize| 942ed69c_700a_469a_9591_07b87815a909
942ed69c_700a_469a_9591_07b87815a909 -->|support::enabled| b1593e0b_1b3b_462d_9ab6_21d1c136469d
b1593e0b_1b3b_462d_9ab6_21d1c136469d -->|support::synergize| 85c8e0dd_b012_402d_bb09_5d354c16ebb9
85c8e0dd_b012_402d_bb09_5d354c16ebb9 -->|support::enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|sequence::preceeds| 518ff777_f10d_4201_9e54_2779c31c512e
```
### Chaining details
#### enabled -> Azure - Storage account reconnaissance (`support::enabled`)
Attackers need to establish an initial presence within the target environment, in 
order to gather sufficient permissions to execute the data collection tools.

- **Target UUID**: `53f4e2f0-7d11-4629-bb26-905993a589db`
#### synergize -> Azure - Storage Account Replication (`support::synergize`)
Adversaries obtains credentials or elevated permissions (via access keys, Service 
Principal abuse, RBAC misconfigurations, or privilege escalation) to the victim’s 
storage account.

- **Target UUID**: `942ed69c-700a-469a-9591-07b87815a909`
#### enabled -> Azure - Gather Resource Data (`support::enabled`)
The attacker obtains credentials (via phishing, password spray, leaked keys) granting 
at least Reader access to the target Azure tenant.

- **Target UUID**: `b1593e0b-1b3b-462d-9ab6-21d1c136469d`
#### synergize -> Azure - Local Resource Hijack (`support::synergize`)
The attacker obtains credentials (via phishing, password spray, leaked keys)
granting at least Reader access to the target Azure tenant.

- **Target UUID**: `85c8e0dd-b012-402d-bb09-5d354c16ebb9`
#### enabled -> Azure - Valid Credentials (`support::enabled`)
Adversaries obtain the username and password of an AzureAD user either through phishing, 
password spraying, brute-force attacks, or credentials leaked online.

- **Target UUID**: `2743bf18-3b86-4721-bf3e-153dcda0b149`
#### preceeds -> Consent phishing attack (`sequence::preceeds`)
User must click on a malicious link sent via email by attackers

- **Target UUID**: `518ff777-f10d-4201-9e54-2779c31c512e`
