# Modify Microsoft Sentinel Data Connector to impair Detections

## Metadata

- **UUID**: `48432b70-77c4-4f5a-9d66-75764c1777c6`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-12-08`
- **Modified**: `2022-12-08`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources](https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources)

## Description
A threat actor may want to disable, remove or update the configuration of
Sentinel Connectors to act invisibly in Azure, which would impair the ability
of a SOC to receive alerts since it would stop log file ingestion into Azure
Sentinel. 

An attacker can do this either by deploying via API an ARM template, biceps
template, or other script/code element that can be used via Azure APIs,
using the Azure CLI or directly on the portal itself via a browser.

## Criticality
**Severe** - A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties.

## Terrain
> **Requires access to privileged Azure credentials

Domains: Public Cloud
Targets: CI/CD Pipelines, System admin
Platforms: Azure**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Highly significant incident | A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy. |
| Impact | Lose Capabilities | Vector execution will remove key functions to the organization, which will not be easily circumvented. Most day-to-day is heavily impaired, but processes can reorganize at a loss. |
| Leverage | Modify configuration | Modify configuration or services |
| Viability | Very Unlikely | Highly improbable - 05-20% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1562.008` | [Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008) | An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment. If an adversary has sufficient permissions, they can disable or modify logging to avoid detection of their activities.  For example, in AWS an adversary may disable CloudWatch/CloudTrail integrations prior to conducting further malicious activity.(Citation: Following the CloudTrail: Generating strong AWS security signals with Sumo Logic) They may alternatively tamper with logging functionality – for example, by removing any associated SNS topics, disabling multi-region logging, or disabling settings that validate and/or encrypt log files.(Citation: AWS Update Trail)(Citation: Pacu Detection Disruption Module) In Office 365, an adversary may disable logging on mail collection activities for specific users by using the `Set-MailboxAuditBypassAssociation` cmdlet, by disabling M365 Advanced Auditing for the user, or by downgrading the user’s license from an Enterprise E5 to an Enterprise E3 license.(Citation: Dark Reading Microsoft 365 Attacks 2021) |
