# Azure - Storage Blobs Reconnaissance

## Metadata

- **UUID**: `41f57a57-1ed6-407e-bb70-a0f6ab52af10`
- **Schema**: `threat::1.0`
- **Version**: `3`
- **Created**: `2025-05-07`
- **Modified**: `2025-09-08`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-blob-storage](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-blob-storage)
- **2**: [https://www.netspi.com/blog/technical-blog/cloud-pentesting/anonymously-enumerating-azure-file-resources/](https://www.netspi.com/blog/technical-blog/cloud-pentesting/anonymously-enumerating-azure-file-resources/)
- **3**: [https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/protect-your-storage-resources-against-blob-hunting/3735238](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/protect-your-storage-resources-against-blob-hunting/3735238)
- **4**: [https://www.inversecos.com/2022/01/how-to-detect-and-compromise-azure.html](https://www.inversecos.com/2022/01/how-to-detect-and-compromise-azure.html)

## Description
Reconnaissance targeting Azure Storage Blobs involves gathering intelligence to identify
exposed storage accounts, containers, and blobs-often without authentication or detection.
Azure’s predictable URL structure, common naming conventions, and potential for
misconfiguration make it a prime target for such activities.

### Discovery of Storage Accounts

- **DNS and Subdomain Enumeration:**  
Each Azure Storage account is accessible via a unique subdomain
(e.g., `yourstorageaccount.blob.core.windows.net`).   
Attackers use DNS enumeration tools (like `dnscan`) and wordlists to guess or 
discover valid storage account names. They often use company names, abbreviations, 
or product names as starting points.

- **Search Engine Dorking:**  
Publicly accessible blobs and containers may be indexed by search engines. Attackers 
leverage advanced search queries (Google dorking), such as `site:*.blob.core.windows.net`, 
to find open blob storage accounts and even specific file types (e.g., `.csv`, `.xlsx`) 
or keywords like `"password"`.

### Enumeration of Containers and Blobs

- **URL Pattern Guessing:**  
Azure Blob Storage uses predictable URL patterns for containers and blobs. Attackers 
automate requests to likely container names (e.g., `backups`, `images`, `prod`) 
and blob names, increasing the odds of finding exposed data.

- **Automated Scanning Tools:**  
Tools like MicroBurst, goblob, and custom scripts are used to automate the enumeration 
of storage accounts, containers, and blobs. These tools can quickly test thousands 
of possible names, scaling up the reconnaissance process.

- **Custom Wordlists:**  
Attackers may build custom dictionaries based on the target’s business, products, 
or previously leaked information to improve the accuracy of their enumeration efforts.

### Analysis of Exposed Data and Metadata

- **Monitoring Access Patterns:**  
By analyzing metadata (timestamps, blob sizes, file types), attackers can infer 
which blobs or containers are most likely to contain sensitive or valuable information.

- **Chaining Exposures:**  
If attackers find an exposed blob, they may discover references within the files 
themselves (e.g., database connection strings, links to other storage accounts), 
allowing them to recursively enumerate and compromise further resources.

### Tenant and Service Enumeration

- **Azure Tenant Discovery:**  
Attackers can leverage known company domains or public APIs to enumerate Azure tenants 
and services, including blob storage endpoints. Tools like MicroBurst and AADInternals 
automate the discovery of tenant IDs and service endpoints, providing additional 
reconnaissance data.

### Reconnaissance Characteristics

- **Silent and Non-Intrusive:**  
Most reconnaissance activities are passive and do not require authentication, making 
them difficult to detect until exploitation occurs.

- **Scalable and Automated:**  
Attackers can automate the entire process, rapidly scanning large numbers of potential 
storage accounts and containers.

### Real-World Impact

- **Sensitive Data Exposure:**  
Even a single misconfigured blob can expose sensitive data, credentials, or internal 
documentation, which can be leveraged for further attacks.

- **Pivoting and Lateral Movement:**  
Exposed blobs may contain information that allows attackers to pivot to other services 
or escalate their access within the target environment.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries must have knowledge about the strucuture of
Azure Blob Storage and naming conventions, and basic
enumeration tools or scripts to carry out 
reconnaissance-especially when misconfigurations or
public access are present.

Domains: Public Cloud
Targets: Cloud Storage Accounts, Public-Facing Servers, API Endpoints, Software Containers, Virtual Machines
Platforms: Azure, Azure AD**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Monetary Loss | - |
| Leverage | Information Disclosure; Infrastructure Compromise; Tampering; Spoofing | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Reconnaissance | Researching, identifying and selecting targets using active or passive reconnaissance. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1530` | [Data from Cloud Storage](https://attack.mitre.org/techniques/T1530) | Adversaries may access data from cloud storage.  Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage. Similarly, SaaS enterprise platforms such as Office 365 and Google Workspace provide cloud-based document storage to users through services such as OneDrive and Google Drive, while SaaS application providers such as Slack, Confluence, Salesforce, and Dropbox may provide cloud storage solutions as a peripheral or primary use case of their platform.   In some cases, as with IaaS-based cloud storage, there exists no overarching application (such as SQL or Elasticsearch) with which to interact with the stored objects: instead, data from these solutions is retrieved directly though the [Cloud API](https://attack.mitre.org/techniques/T1059/009). In SaaS applications, adversaries may be able to collect this data directly from APIs or backend cloud storage objects, rather than through their front-end application or interface (i.e., [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)).   Adversaries may collect sensitive data from these cloud storage solutions. Providers typically offer security guides to help end users configure systems, though misconfigurations are a common problem.(Citation: Amazon S3 Security, 2019)(Citation: Microsoft Azure Storage Security, 2019)(Citation: Google Cloud Storage Best Practices, 2019) There have been numerous incidents where cloud storage has been improperly secured, typically by unintentionally allowing public access to unauthenticated users, overly-broad access by all users, or even access for any anonymous person outside the control of the Identity Access Management system without even needing basic user permissions.  This open access may expose various types of sensitive data, such as credit cards, personally identifiable information, or medical records.(Citation: Trend Micro S3 Exposed PII, 2017)(Citation: Wired Magecart S3 Buckets, 2019)(Citation: HIPAA Journal S3 Breach, 2017)(Citation: Rclone-mega-extortion_05_2021)  Adversaries may also obtain then abuse leaked credentials from source repositories, logs, or other means as a way to gain access to cloud storage objects. |
| `T1552` | [Unsecured Credentials](https://attack.mitre.org/techniques/T1552) | Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)),  or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).(Citation: Brining MimiKatz to Unix) |
| `T1619` | [Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) | Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage.  Similar to [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) on a local host, after identifying available storage services (i.e. [Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580)) adversaries may access the contents/objects stored in cloud infrastructure.  Cloud service providers offer APIs allowing users to enumerate objects stored within cloud storage. Examples include ListObjectsV2 in AWS (Citation: ListObjectsV2) and List Blobs in Azure(Citation: List Blobs) . |
| `T1567` | [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567) | Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.  Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection. |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |

## Chaining
```mermaid
flowchart LR
41f57a57_1ed6_407e_bb70_a0f6ab52af10["Azure - Storage Blobs Reconnaissance"]
53f4e2f0_7d11_4629_bb26_905993a589db["Azure - Storage account reconnaissance"]
2743bf18_3b86_4721_bf3e_153dcda0b149["Azure - Valid Credentials"]
b1593e0b_1b3b_462d_9ab6_21d1c136469d["Azure - Gather Resource Data"]
53063205_4404_4e6d_a2f5_d566c6085d96["Data collection using SharpHound, SoapHound, Bloodhound and Azurehound"]
41f57a57_1ed6_407e_bb70_a0f6ab52af10 -->|support::enabled| 53f4e2f0_7d11_4629_bb26_905993a589db
53f4e2f0_7d11_4629_bb26_905993a589db -->|support::enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|support::enabled| b1593e0b_1b3b_462d_9ab6_21d1c136469d
b1593e0b_1b3b_462d_9ab6_21d1c136469d -->|support::enabled| 53063205_4404_4e6d_a2f5_d566c6085d96
```
### Chaining details
#### enabled -> Azure - Storage account reconnaissance (`support::enabled`)
Adversaries need to scan and discover publicly accessible storage containers by 
guessing or enumerating storage account and container names.

- **Target UUID**: `53f4e2f0-7d11-4629-bb26-905993a589db`
#### enabled -> Azure - Valid Credentials (`support::enabled`)
Adversaries obtain the username and password of an AzureAD user either through phishing, 
password spraying, brute-force attacks, or credentials leaked online.

- **Target UUID**: `2743bf18-3b86-4721-bf3e-153dcda0b149`
#### enabled -> Azure - Gather Resource Data (`support::enabled`)
The attacker obtains credentials (via phishing, password spray, leaked keys) granting 
at least Reader access to the target Azure tenant.

- **Target UUID**: `b1593e0b-1b3b-462d-9ab6-21d1c136469d`
#### enabled -> Data collection using SharpHound, SoapHound, Bloodhound and Azurehound (`support::enabled`)
Attackers need to establish an initial presence within the target environment, in 
order to gather sufficient permissions to execute the data collection tools.

- **Target UUID**: `53063205-4404-4e6d-a2f5-d566c6085d96`
