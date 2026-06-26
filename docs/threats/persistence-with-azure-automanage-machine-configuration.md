# Persistence with Azure Automanage Machine Configuration

## Metadata

- **UUID**: `23f6a192-a25d-48b8-a235-7bb55e483682`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2022-04-28`
- **Modified**: `2023-01-06`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://cloudbrothers.info/azure-persistence-azure-policy-guest-configuration/#:~:text=Azure%20Policy%20enables%20administrators%20to,configuration%20feature%20of%20Azure%20Policy.](https://cloudbrothers.info/azure-persistence-azure-policy-guest-configuration/#:~:text=Azure%20Policy%20enables%20administrators%20to,configuration%20feature%20of%20Azure%20Policy.)

## Description
Azure Policy enables administrators to define, enforce and remediate
configuration standards on Azure resources and even on non Azure assets
using Azure Arc. One key feature, that was released in 2021, is the
guest configuration feature of Azure Policy. Azure Policy Guest 
Configuration is now called Azure Automanage Machine Configuration. 

Adversaries may use this functionality to gain persistence in an Azure 
environment if they have gained the necessary permissions within the 
subscription. And since Azure VMs are in many cases directly integrated 
in the on-Premises Active Directory it is possible to gain additional 
access there.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **The adversary needs the owner access role on the targeted Azure 
Subscription to apply the Azure Policy and grant permissions for
the system-managed identities.

Domains: Public Cloud
Targets: Virtual Machines
Platforms: Azure**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Business disruption; Data Breach; Impairement | - |
| Leverage | Infrastructure Compromise; Dwelling; Modify privileges | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1484.001` | [Domain or Tenant Policy Modification: Group Policy Modification](https://attack.mitre.org/techniques/T1484/001) | Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path `\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`.(Citation: TechNet Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016)   Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain.  Malicious GPO modifications can be used to implement many other malicious behaviors such as [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001), [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105), [Create Account](https://attack.mitre.org/techniques/T1136), [Service Execution](https://attack.mitre.org/techniques/T1569/002),  and more.(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions)(Citation: Mandiant M Trends 2016)(Citation: Microsoft Hacking Team Breach) Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse.(Citation: Wald0 Guide to GPOs)  For example, publicly available scripts such as <code>New-GPOImmediateTask</code> can be leveraged to automate the creation of a malicious [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) by modifying GPO settings, in this case modifying <code>&lt;GPO_PATH&gt;\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml</code>.(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in <code>&lt;GPO_PATH&gt;\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf</code>, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs.(Citation: Harmj0y SeEnableDelegationPrivilege Right) |
