# Azure - External Entity Access

## Metadata
| Field | Value |
| --- | --- |
| UUID | `31e7f292-8370-4255-861d-edd68ed8b7b0` |
| Schema | `threat::1.0` |
| Version | `1` |
| Created | `2025-09-22` |
| Modified | `2025-09-22` |
| TLP | clear (`TLP:CLEAR`) |
| Organisation | EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`) |

## References
### Public
- **1**: [https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT507/AZT507/](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT507/AZT507/)
- **2**: [https://docs.azure.cn/en-us/entra/architecture/1-secure-access-posture](https://docs.azure.cn/en-us/entra/architecture/1-secure-access-posture)

## Description
The following threat vector refers to a set of persistence techniques where an adversary 
configures a target Azure tenant to be managed or accessed by external entities, 
such as another tenant, external users, or identity providers. This section provides 
in-depth coverage of this threat vector according to the Azure Threat Research Matrix, 
addressing scenario, goals, impact, and methodology.

### Example Attack Scenario

An attacker gains Global Administrator privileges in a compromised tenant and uses Azure 
Lighthouse to register an external, attacker-controlled tenant as a delegated administrator. 
This allows the attacker to manage resources and maintain persistence even if their 
initial account is detected and removed. Alternatively, the attacker might use Microsoft 
Partner Delegated Administrative Privileges, transfer a subscription (“subscription hijack”), 
or add a new federated domain or identity provider, creating hidden backdoors for 
future access.

- For example, after compromising credentials, an attacker uses Microsoft Graph 
API to modify tenant settings and register their own tenant as a manager via Azure Lighthouse.
- The administrator in the compromised tenant is unaware as delegated permissions 
silently persist, giving the attacker full control over resources and users.
- Even after password resets or removal of individual malicious accounts, the external 
entity persists via configuration and cannot be easily detected without deep audit 
review of resource assignments and domain trusts.

### Attack Goals and Impact

The main goal is to establish persistence inside the target Azure environment through 
external entity control.

- Maintain long-term, resilient access to cloud resources, regardless of changes 
in local credentials or account clean-ups.
- Allow management of resources remotely from attacker-controlled tenants.
- Facilitate lateral movement, data exfiltration, or further privilege escalation 
by leveraging cross-tenant capabilities and hidden delegated privileges.

The impact may include:

- Full compromise of cloud assets and data.
- Unnoticed attacker presence persisting through routine security hygiene (such as credential revocation).
- Increased difficulty for defenders to detect or remove persistent access mechanisms.

### Attack Flow and Methodology

The typical attack flow involves several steps:

1. Privilege abuse: The attacker uses available tools (including Microsoft Graph 
API, PowerShell modules, or Azure Portal) to grant management rights or delegated 
access to an external entity (such as Azure Lighthouse, Microsoft Partner delegation, 
or domain trust modification).
2. Configuration: The attacker registers their external tenant, sets up delegated 
access, or modifies domain trust/federation settings to establish a persistent link.
3. Stealthy persistence: Even if initial access accounts/credentials are remediated, 
the external entity retains management capabilities—allowing the attacker to create 
new accounts, manage resources, or harvest sensitive data.
4. Maintenance: The attacker periodically refreshes delegated permissions, adds 
new external users/entities, or modifies trust relationships as needed to maintain 
access and evade detection.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
Adversaries gains administrative access (e.g., via phishing, credential theft,
or exploiting vulnerabilities).

## Surface
> **Azure**
> Microsoft Azure cloud platform

> **Azure::Security::Entra ID**
> Microsoft Entra ID in Azure (cloud identity)

> **Windows**
> Microsoft Windows operating systems (all versions)

> **AWS::Storage**
> AWS storage services

> **Entra ID**
> Microsoft Entra ID (formerly Azure Active Directory)

> **Azure::Compute::Virtual Machines**
> Azure Virtual Machines

> **Application Layer::HTTP**
> Hypertext Transfer Protocol

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach<br>IP Loss<br>Reputational Damages<br>Identity Theft<br>Monetary Loss | Non-public information has been accessed from the outside, and successfully extracted.<br>Particular, key data, information and blueprint conducive to the organization capability to gain and retain a commercial or geopolitical advantage has been accessed, and their content potentially used by competitors or other adversaries.<br>Damages to the organization public view may be achieved by using directly the access gained, or indirectly with data gathered.<br>Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.<br>The vector will directly conduct to loss of value directly impacting the bottom line. |
| Leverage | Elevation of privilege<br>Infrastructure Compromise<br>Information Disclosure<br>Modify configuration | Capacity to augment leverage over the target system by upgrading the compromised access rights<br>The compromised target is likely to be used to further expand the sphere of influence of the attacker and allow more potent vectors to be executed.<br>Threat action intending to read a file that one was not granted access to, or to read data in transit.<br>Modify configuration or services |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| Scattered Spider | `misp::3b238f3a-c67a-4a9e-b474-dc3897e00129` | ('misp',) | Scattered Spider, a highly active hacking group, has made headlines by targeting more than 130 organizations, with the number of victims steadily increasing. |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1133` | [External Remote Services](https://attack.mitre.org/techniques/T1133) | Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)  Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.  Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware) |
| `T1484.002` | [Domain or Tenant Policy Modification: Trust Modification](https://attack.mitre.org/techniques/T1484/002) | Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whether or not user identities are federated, allow authentication and authorization properties to apply between domains or tenants for the purpose of accessing shared resources.(Citation: Microsoft - Azure AD Federation) These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.  Manipulating these trusts may allow an adversary to escalate privileges and/or evade defenses by modifying settings to add objects which they control. For example, in Microsoft Active Directory (AD) environments, this may be used to forge [SAML Tokens](https://attack.mitre.org/techniques/T1606/002) without the need to compromise the signing certificate to forge new credentials. Instead, an adversary can manipulate domain trusts to add their own signing certificate. An adversary may also convert an AD domain to a federated domain using Active Directory Federation Services (AD FS), which may enable malicious trust modifications such as altering the claim issuance rules to log in any valid set of credentials as a specified user.(Citation: AADInternals zure AD Federated Domain)   An adversary may also add a new federated identity provider to an identity tenant such as Okta or AWS IAM Identity Center, which may enable the adversary to authenticate as any user of the tenant.(Citation: Okta Cross-Tenant Impersonation 2023) This may enable the threat actor to gain broad access into a variety of cloud-based services that leverage the identity tenant. For example, in AWS environments, an adversary that creates a new identity provider for an AWS Organization will be able to federate into all of the AWS Organization member accounts without creating identities for each of the member accounts.(Citation: AWS RE:Inforce Threat Detection 2024) |
| `T1078.004` | [Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) | Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. Cloud Accounts can exist solely in the cloud; alternatively, they may be hybrid-joined between on-premises systems and the cloud through syncing or federation with other identity sources such as Windows Active Directory.(Citation: AWS Identity Federation)(Citation: Google Federating GC)(Citation: Microsoft Deploying AD Federation)  Service or user accounts may be targeted by adversaries through [Brute Force](https://attack.mitre.org/techniques/T1110), [Phishing](https://attack.mitre.org/techniques/T1566), or various other means to gain access to the environment. Federated or synced accounts may be a pathway for the adversary to affect both on-premises systems and cloud environments - for example, by leveraging shared credentials to log onto [Remote Services](https://attack.mitre.org/techniques/T1021). High privileged cloud accounts, whether federated, synced, or cloud-only, may also allow pivoting to on-premises environments by leveraging SaaS-based [Software Deployment Tools](https://attack.mitre.org/techniques/T1072) to run commands on hybrid-joined devices.  An adversary may create long lasting [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) on a compromised cloud account to maintain persistence in the environment. Such credentials may also be used to bypass security controls such as multi-factor authentication.   Cloud accounts may also be able to assume [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) or other privileges through various means within the environment. Misconfigurations in role assignments or role assumption policies may allow an adversary to use these mechanisms to leverage permissions outside the intended scope of the account. Such over privileged accounts may be used to harvest sensitive data from online storage accounts and databases through [Cloud API](https://attack.mitre.org/techniques/T1059/009) or other methods. For example, in Azure environments, adversaries may target Azure Managed Identities, which allow associated Azure resources to request access tokens. By compromising a resource with an attached Managed Identity, such as an Azure VM, adversaries may be able to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s to move laterally across the cloud environment.(Citation: SpecterOps Managed Identity 2022) |

## Chaining
```mermaid
flowchart LR
subgraph "Persistence"
31e7f292_8370_4255_861d_edd68ed8b7b0{{"Azure - External Entity<br>Access"}}
5d43ef75_4637_4a75_b1ed_6716052cff0e{{"Azure - App registration<br>persistence"}}
bcf3bb96_ed97_4853_98ab_937c2d214f4e{{"Azure - Key Vault<br>persistence"}}
50c7e353_ac1c_48a7_8c98_2515b45f31f4{{"Persistence through<br>automation runbooks in<br>Azure"}}
23f6a192_a25d_48b8_a235_7bb55e483682{{"Persistence with Azure<br>Automanage Machine<br>Configuration"}}
end
subgraph "Reconnaissance"
53063205_4404_4e6d_a2f5_d566c6085d96{{"Data collection using<br>SharpHound, SoapHound,<br>Bloodhound and<br>Azurehound"}}
4e7eae8e_6615_41f2_bfe1_21a04f7a6088{{"Azure - Gather Victim<br>Data"}}
2900d389_3098_49d3_8166_5b2612d03576{{"Azure - Gather User<br>Information"}}
fe6827f2_efb4_43b3_9ca3_b7d417111b32{{"Azure - Gather<br>Application Information"}}
140907eb_c9fb_4330_9d71_656422388b2b{{"Azure - Gather Role<br>Information"}}
end
subgraph "Privilege Escalation"
10a89280_d42e_446d_9f8d_840b1218f532{{"Azure - Elevated Access<br>Toggle"}}
c698fc79_3ed6_44a7_a9d7_bc447600e4c3{{"Azure AD Connect abuse"}}
c7e260d8_d391_41eb_be1a_7f276c99b383{{"Azure app registration -<br>privilege escalation"}}
bb2501d5_99c7_44a6_ac5a_9510102d6611{{"Azure - Principal<br>Impersonation"}}
f1dc4341_eb45_4d07_8075_b1a6b227cc76{{"Cloud IAM role<br>assumption"}}
end
subgraph "Credential Access"
2743bf18_3b86_4721_bf3e_153dcda0b149{{"Azure - Valid<br>Credentials"}}
6a7a493a_511a_4c9d_aa9c_4427c832a322{{"SIM-card swapping"}}
4a807ac4_f764_41b1_ae6f_94239041d349{{"MFA Bypass Techniques"}}
66aafb61_9a46_4287_8b40_4785b42b77a3{{"Adversary in the Middle<br>phishing sites to bypass<br>MFA"}}
6e988fa7_69c9_4aef_897c_a34fa5066dac{{"Ghost logins attempts"}}
end
subgraph "Command & Control"
2fd1cddb_c66d_4a99_9779_31e32b67495e{{"Azure - Lateral movement<br>abusing Cross-Tenant<br>Synchronization"}}
end
subgraph "Lateral Movement"
9bb31c65_8abd_48fc_afe3_8aca76109737{{"Azure - Modify<br>federation trust to<br>accept externally signed<br>tokens"}}
a8c7b250_a2d4_4a0d_82f8_23dc99c77d7b{{"Addition of credentials<br>to OAuth applications<br>and service principals"}}
ca2751c7_8641_4fb0_a90b_30c5987015dc{{"Externally controlled<br>Azure credentials added<br>to an Enterprise app or<br>its SPN"}}
end
subgraph "Delivery"
1a68b5eb_0112_424d_a21f_88dda0b6b8df{{"Spearphishing Link"}}
dd5d942c_bac4_4000_b9a6_ca4fef6cfb84{{"Spearphishing Attachment"}}
58b98d75_fc63_4662_8908_a2a7f4200902{{"Spearphishing with an<br>attachment extension<br>.rdp"}}
06c60af1_5fa8_493c_bf9b_6b2e215819f1{{"Social engineering<br>attack using Microsoft<br>Teams"}}
end
subgraph "Social Engineering"
0cdaee96_8595_4f3f_ba07_758b8be9d359{{"Social engineering<br>without attachment or<br>URL"}}
end
subgraph "Execution"
60c5b065_7d06_4697_850f_c2f80765f10b{{"Changes to Azure<br>infrastructure deployed<br>through Azure CLI"}}
61ddc240_e5a6_4ca8_ae77_6b471b498913{{"Code execution via<br>custom script extensions<br>in Azure"}}
end
subgraph "Collection"
78d5e363_14db_40c0_a1c4_4ba02a3e60d4{{"Azure - Hijack Entra ID<br>Applications"}}
f18be76e_f2b3_410a_80c5_d67e7b8e7b03{{"Perform Microsoft Entra<br>ID connectors MITM<br>attack"}}
end
20bd3620_b13b_4895_b291_b1a26bd9aef3{{"MS 365 admin compromised<br>account"}}
31e7f292_8370_4255_861d_edd68ed8b7b0 -->|enabled| 53063205_4404_4e6d_a2f5_d566c6085d96
31e7f292_8370_4255_861d_edd68ed8b7b0 -->|enabled| 10a89280_d42e_446d_9f8d_840b1218f532
31e7f292_8370_4255_861d_edd68ed8b7b0 -->|enabled| 4e7eae8e_6615_41f2_bfe1_21a04f7a6088
31e7f292_8370_4255_861d_edd68ed8b7b0 -->|enabled| 2900d389_3098_49d3_8166_5b2612d03576
31e7f292_8370_4255_861d_edd68ed8b7b0 -->|implemented| 2743bf18_3b86_4721_bf3e_153dcda0b149
31e7f292_8370_4255_861d_edd68ed8b7b0 -->|implemented| 4e7eae8e_6615_41f2_bfe1_21a04f7a6088
31e7f292_8370_4255_861d_edd68ed8b7b0 <-->|synergize| 2fd1cddb_c66d_4a99_9779_31e32b67495e
31e7f292_8370_4255_861d_edd68ed8b7b0 <-->|synergize| 9bb31c65_8abd_48fc_afe3_8aca76109737
53063205_4404_4e6d_a2f5_d566c6085d96 -->|succeeds| 1a68b5eb_0112_424d_a21f_88dda0b6b8df
53063205_4404_4e6d_a2f5_d566c6085d96 -->|succeeds| dd5d942c_bac4_4000_b9a6_ca4fef6cfb84
10a89280_d42e_446d_9f8d_840b1218f532 -->|succeeds| 2900d389_3098_49d3_8166_5b2612d03576
10a89280_d42e_446d_9f8d_840b1218f532 -->|succeeds| 2743bf18_3b86_4721_bf3e_153dcda0b149
10a89280_d42e_446d_9f8d_840b1218f532 -->|preceeds| 5d43ef75_4637_4a75_b1ed_6716052cff0e
10a89280_d42e_446d_9f8d_840b1218f532 -->|preceeds| bcf3bb96_ed97_4853_98ab_937c2d214f4e
2900d389_3098_49d3_8166_5b2612d03576 -->|succeeds| 58b98d75_fc63_4662_8908_a2a7f4200902
2900d389_3098_49d3_8166_5b2612d03576 -->|succeeds| 0cdaee96_8595_4f3f_ba07_758b8be9d359
2900d389_3098_49d3_8166_5b2612d03576 -->|succeeds| 06c60af1_5fa8_493c_bf9b_6b2e215819f1
58b98d75_fc63_4662_8908_a2a7f4200902 -->|implements| dd5d942c_bac4_4000_b9a6_ca4fef6cfb84
0cdaee96_8595_4f3f_ba07_758b8be9d359 -->|preceeds| 1a68b5eb_0112_424d_a21f_88dda0b6b8df
0cdaee96_8595_4f3f_ba07_758b8be9d359 -->|preceeds| dd5d942c_bac4_4000_b9a6_ca4fef6cfb84
0cdaee96_8595_4f3f_ba07_758b8be9d359 -->|preceeds| 6a7a493a_511a_4c9d_aa9c_4427c832a322
6a7a493a_511a_4c9d_aa9c_4427c832a322 -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| a8c7b250_a2d4_4a0d_82f8_23dc99c77d7b
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 66aafb61_9a46_4287_8b40_4785b42b77a3
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| c698fc79_3ed6_44a7_a9d7_bc447600e4c3
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 5d43ef75_4637_4a75_b1ed_6716052cff0e
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 60c5b065_7d06_4697_850f_c2f80765f10b
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 6e988fa7_69c9_4aef_897c_a34fa5066dac
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 78d5e363_14db_40c0_a1c4_4ba02a3e60d4
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 2fd1cddb_c66d_4a99_9779_31e32b67495e
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 20bd3620_b13b_4895_b291_b1a26bd9aef3
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| f18be76e_f2b3_410a_80c5_d67e7b8e7b03
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 50c7e353_ac1c_48a7_8c98_2515b45f31f4
2743bf18_3b86_4721_bf3e_153dcda0b149 -->|preceeds| 23f6a192_a25d_48b8_a235_7bb55e483682
66aafb61_9a46_4287_8b40_4785b42b77a3 -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
c698fc79_3ed6_44a7_a9d7_bc447600e4c3 -->|enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
5d43ef75_4637_4a75_b1ed_6716052cff0e -->|succeeds| c7e260d8_d391_41eb_be1a_7f276c99b383
c7e260d8_d391_41eb_be1a_7f276c99b383 -->|enabled| bb2501d5_99c7_44a6_ac5a_9510102d6611
c7e260d8_d391_41eb_be1a_7f276c99b383 -->|enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
c7e260d8_d391_41eb_be1a_7f276c99b383 -->|enabled| fe6827f2_efb4_43b3_9ca3_b7d417111b32
bb2501d5_99c7_44a6_ac5a_9510102d6611 -->|preceeds| 2743bf18_3b86_4721_bf3e_153dcda0b149
bb2501d5_99c7_44a6_ac5a_9510102d6611 -->|preceeds| fe6827f2_efb4_43b3_9ca3_b7d417111b32
6e988fa7_69c9_4aef_897c_a34fa5066dac -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
fe6827f2_efb4_43b3_9ca3_b7d417111b32 -->|enabled| 140907eb_c9fb_4330_9d71_656422388b2b
fe6827f2_efb4_43b3_9ca3_b7d417111b32 -->|enabled| 53063205_4404_4e6d_a2f5_d566c6085d96
fe6827f2_efb4_43b3_9ca3_b7d417111b32 -->|enabling| ca2751c7_8641_4fb0_a90b_30c5987015dc
fe6827f2_efb4_43b3_9ca3_b7d417111b32 -->|enabling| c7e260d8_d391_41eb_be1a_7f276c99b383
140907eb_c9fb_4330_9d71_656422388b2b -->|preceeds| a8c7b250_a2d4_4a0d_82f8_23dc99c77d7b
140907eb_c9fb_4330_9d71_656422388b2b -->|preceeds| 61ddc240_e5a6_4ca8_ae77_6b471b498913
140907eb_c9fb_4330_9d71_656422388b2b -->|preceeds| f1dc4341_eb45_4d07_8075_b1a6b227cc76
61ddc240_e5a6_4ca8_ae77_6b471b498913 -->|enabled| 140907eb_c9fb_4330_9d71_656422388b2b
61ddc240_e5a6_4ca8_ae77_6b471b498913 -->|enabled| 2743bf18_3b86_4721_bf3e_153dcda0b149
4e7eae8e_6615_41f2_bfe1_21a04f7a6088 -->|preceeds| dd5d942c_bac4_4000_b9a6_ca4fef6cfb84
4e7eae8e_6615_41f2_bfe1_21a04f7a6088 -->|preceeds| 1a68b5eb_0112_424d_a21f_88dda0b6b8df
```
### Chaining details
#### enabled -> [Data collection using SharpHound, SoapHound, Bloodhound and Azurehound](data-collection-using-sharphound-soaphound-bloodhound-and-azurehound.md) (`53063205-4404-4e6d-a2f5-d566c6085d96`) (`support::enabled`)
Attackers need to establish an initial presence within the target environment, in 
order to gather sufficient permissions to execute the data collection tools.

- **Target UUID**: `53063205-4404-4e6d-a2f5-d566c6085d96`
#### enabled -> [Azure - Elevated Access Toggle](azure-elevated-access-toggle.md) (`10a89280-d42e-446d-9f8d-840b1218f532`) (`support::enabled`)
Adversaries successfully compromise a Global Administrator account in
 Entra ID (Azure AD), either via phishing, credential theft, or session hijacking.

- **Target UUID**: `10a89280-d42e-446d-9f8d-840b1218f532`
#### enabled -> [Azure - Gather Victim Data](azure-gather-victim-data.md) (`4e7eae8e-6615-41f2-bfe1-21a04f7a6088`) (`support::enabled`)
An adversary successfully compromises a user's Azure Active Directory account credentials 
or session token through phishing, credential theft, or token theft.

- **Target UUID**: `4e7eae8e-6615-41f2-bfe1-21a04f7a6088`
#### implemented -> [Azure - Valid Credentials](azure-valid-credentials.md) (`2743bf18-3b86-4721-bf3e-153dcda0b149`) (`atomicity::implemented`)
Adversaries obtain the username and password of an AzureAD user either through phishing, 
password spraying, brute-force attacks, or credentials leaked online.

- **Target UUID**: `2743bf18-3b86-4721-bf3e-153dcda0b149`
#### enabled -> [Azure - Gather User Information](azure-gather-user-information.md) (`2900d389-3098-49d3-8166-5b2612d03576`) (`support::enabled`)
Adversaries use publicly accessible endpoints, misconfigured applications, or phishing 
emails to harvest user names, email addresses, job titles, and group memberships.

- **Target UUID**: `2900d389-3098-49d3-8166-5b2612d03576`
#### implemented -> [Azure - Gather Victim Data](azure-gather-victim-data.md) (`4e7eae8e-6615-41f2-bfe1-21a04f7a6088`) (`atomicity::implemented`)
An adversary may access a user's personal data if their account is compromised.
This includes data such as email, OneDrive, Teams, etc.

- **Target UUID**: `4e7eae8e-6615-41f2-bfe1-21a04f7a6088`
#### synergize -> [Azure - Lateral movement abusing Cross-Tenant Synchronization](azure-lateral-movement-abusing-cross-tenant-synchronization.md) (`2fd1cddb-c66d-4a99-9779-31e32b67495e`) (`support::synergize`)
Attackers must have compromised a tenant and gained elevated privileges.

- **Target UUID**: `2fd1cddb-c66d-4a99-9779-31e32b67495e`
#### synergize -> [Azure - Modify federation trust to accept externally signed tokens](azure-modify-federation-trust-to-accept-externally-signed-tokens.md) (`9bb31c65-8abd-48fc-afe3-8aca76109737`) (`support::synergize`)
Attackers need to have gained administrative Azure Active Directory
(Azure AD) privileges using compromised credentials.

- **Target UUID**: `9bb31c65-8abd-48fc-afe3-8aca76109737`
