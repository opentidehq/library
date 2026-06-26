# IP Discovery in Azure

## Metadata

- **UUID**: `777e22c5-e47d-42a2-a803-42a101dee575`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-07-30`
- **Modified**: `2025-08-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://microsoft.github.io/Azure-Threat-Research-Matrix/Reconnaissance/AZT102/AZT102/](https://microsoft.github.io/Azure-Threat-Research-Matrix/Reconnaissance/AZT102/AZT102/)

## Description
IP Discovery in the context of Azure refers to an adversary’s technique for identifying 
the public IP addresses associated with Azure resources. This activity is classified 
in the Azure Threat Research Matrix (ATRM) under **reconnaissance** tactics, because 
it is often one of the first steps attackers perform to understand the accessible 
surface of a target Azure environment.

#### Attack Flow and Methodology

1. **Initial Reconnaissance**  (see terrain)
  The attacker needs valid credentials or otherwise access to an Azure environment 
  
2. **Enumerating Resources**  
  Using the Azure Portal, the Azure CLI, PowerShell, or Azure REST APIs, they enumerate 
  resources—especially focusing on Virtual Machines (VMs) and Network Interfaces (NICs).

3. **Querying for IP Information**  
  The attacker issues read requests (such as `az network nic list`, `Get-AzNetworkInterface`, 
  or relevant API calls) to retrieve detailed information about NICs. Each NIC 
  object includes properties for associated public and private IP addresses.

4. **Mapping IPs to VMs**  
  From the NIC information, the adversary can link public IPs back to specific 
  VMs or other endpoints, thereby building a map of accessible resources and potential 
  entry points.

#### Attack Goals and Impact

- **Surface Mapping:** Generate a list of exposed public IP addresses and their 
associated Azure resources.
- **Prioritizing Targets:** Identify potentially vulnerable endpoints for direct 
attack (RDP, SSH, web services) or for scanning later.
- **Avoiding Detection:** Reconnaissance is “low and slow”—often blends in with 
administrative activity, making detection challenging unless closely monitored.

#### Example Attack Scenario

1. **Enumeration:**  
  ```
  az network nic list --query "[].{Name:name, IP:ipConfigurations[].publicIpAddress.id}"
  ```
  Or use the Azure REST API to enumerate all NICs and their attached public IPs.

2. **Data Correlation:**  
  Map discovered IPs to VMs using the relationships expressed in the Azure resource objects.

3. **Follow-Up:**  
  The attacker now has a list of direct IPs to probe for vulnerabilities 
  (e.g., open RDP or SSH ports, misconfigured firewalls).

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversary must have access to an Azure environment, either through compromised
credentials, exposed keys, or abused privileges, and be able to use Azure Portal,
Azure CLI, PowerShell, or Azure REST APIs.

Domains: Public Cloud, Private Cloud
Targets: Virtual Machines, Public-Facing Servers, Cloud Storage Accounts, Cloud Portal
Platforms: Azure, Azure AD, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Business disruption | - |
| Leverage | Information Disclosure; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Reconnaissance | Researching, identifying and selecting targets using active or passive reconnaissance. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1078` | [Valid Accounts](https://attack.mitre.org/techniques/T1078) | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.(Citation: volexity_0day_sophos_FW) Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.  In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.(Citation: CISA MFA PrintNightmare)  The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.(Citation: TechNet Credential Theft) |
| `T1526` | [Cloud Service Discovery](https://attack.mitre.org/techniques/T1526) | An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Entra ID, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs.  Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Microsoft Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.(Citation: Azure - Resource Manager API)(Citation: Azure AD Graph API)  For example, Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services.(Citation: Azure - Stormspotter)(Citation: GitHub Pacu)  Adversaries may use the information gained to shape follow-on behaviors, such as targeting data or credentials from enumerated services or evading identified defenses through [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001) or [Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008). |
| `T1528` | [Steal Application Access Token](https://attack.mitre.org/techniques/T1528) | Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.  Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019)  Adversaries who steal account API tokens in cloud and containerized environments may be able to access data and perform actions with the permissions of these accounts, which can lead to privilege escalation and further compromise of the environment.  For example, in Kubernetes environments, processes running inside a container may communicate with the Kubernetes API server using service account tokens. If a container is compromised, an adversary may be able to steal the container’s token and thereby gain access to Kubernetes API commands.(Citation: Kubernetes Service Accounts)    Similarly, instances within continuous-development / continuous-integration (CI/CD) pipelines will often use API tokens to authenticate to other services for testing and deployment.(Citation: Cider Security Top 10 CICD Security Risks) If these pipelines are compromised, adversaries may be able to steal these tokens and leverage their privileges.   In Azure, an adversary who compromises a resource with an attached Managed Identity, such as an Azure VM, can request short-lived tokens through the Azure Instance Metadata Service (IMDS). These tokens can then facilitate unauthorized actions or further access to other Azure services, bypassing typical credential-based authentication.(Citation: Entra Managed Identities 2025)(Citation: SpecterOps Managed Identity 2022)  Token theft can also occur through social engineering, in which case user action may be required to grant access. OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow.(Citation: Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code Authorization flow - June 2019) An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials.    Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token.(Citation: Amnesty OAuth Phishing Attacks, August 2019)(Citation: Trend Micro Pawn Storm OAuth 2017) The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls.(Citation: Microsoft - Azure AD App Registration - May 2019) Then, they can send a [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through [Application Access Token](https://attack.mitre.org/techniques/T1550/001).(Citation: Microsoft - Azure AD Identity Tokens - Aug 2019)  Application access tokens may function within a limited lifetime, limiting how long an adversary can utilize the stolen token. However, in some cases, adversaries can also steal application refresh tokens(Citation: Auth0 Understanding Refresh Tokens), allowing them to obtain new access tokens without prompting the user. |
