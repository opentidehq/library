# AWS Stop Logging CloudTrail

## Metadata

- **UUID**: `d370aaea-c3e5-4d58-a6c9-3d1a7ffe50e3`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2024-10-31`
- **Modified**: `2024-10-31`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/stopping-cloudtrail-trail/](https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/stopping-cloudtrail-trail/)
- **2**: [https://research.splunk.com/cloud/0b78a8f9-1d31-4d23-85c8-56ad13d5b4c1/](https://research.splunk.com/cloud/0b78a8f9-1d31-4d23-85c8-56ad13d5b4c1/)

## Description
### AWS Stop Logging CloudTrail Threat

The "AWS Stop Logging CloudTrail" threat is a malicious action where an attacker 
deliberately disables AWS CloudTrail logging. This intentional act poses a significant 
risk to AWS users, and understanding its nature, purpose, and implications is crucial 
for maintaining and protecting CloudTrail logs.

### Nature of the Threat

1. **Definition**: It's an intentional act to stop AWS CloudTrail from recording 
API activity and events within an AWS account.
2. **Method**: The attacker uses the AWS API, specifically the `StopLogging` operation 
on a CloudTrail trail.
3. **Target**: The primary target is the CloudTrail service, which is responsible 
for logging and monitoring AWS account activity.

### Purpose and Motivation

1. **Evasion**: The main goal is to evade detection by stopping the recording of 
actions taken in the AWS environment.
2. **Concealment**: Attackers aim to hide their tracks and prevent their activities 
from being logged.
3. **Persistence**: By disabling logging, attackers can maintain access and perform 
actions without leaving a trail.

### Potential Impact

1. **Loss of Audit Trail**: Critical information about API calls and account activity 
is no longer recorded.
2. **Compliance Violations**: Many regulatory standards require continuous logging, 
which this threat violates.
3. **Increased Vulnerability**: Without logs, identifying and responding to other 
security incidents becomes significantly harder.
4. **Extended Attacker Freedom**: Attackers can perform various malicious activities 
without fear of being logged.
5. **Data Loss**: Any actions performed while logging is disabled are permanently 
lost and cannot be retroactively captured.

### Broader Implications

1. **Part of Larger Attacks**: This action is often part of a more extensive attack 
strategy, potentially indicating a sophisticated adversary.
2. **Indicator of Compromise**: The act of stopping CloudTrail logging is itself 
a strong indicator that an account has been compromised.
3. **Time-Sensitive Impact**: Every moment CloudTrail logging remains disabled increases 
the potential damage and loss of critical audit information.

### Identifying the Threat

StopLogging is a critical action that adversaries may use to evade detection. By 
halting the logging of their malicious activities, attackers aim to operate undetected 
within a compromised AWS environment. Identifying such behavior is important, as 
it signals an attempt to undermine the integrity of logging mechanisms, potentially 
allowing malicious activities to proceed without observation. The impact of this 
evasion tactic is significant, as it can severely hamper incident response and forensic 
investigations by obscuring the attacker's actions.

## Criticality
**Low** - A Low priority incident is unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor requires authenticated access with permissions 
cloudtrail:StopLogging to execute the StopLogging API call.

Domains: Public Cloud, Private Cloud
Targets: IaaS
Platforms: AWS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement; Lose Capabilities | - |
| Leverage | Log tampering; Modify configuration; Repudiation | - |
| Viability | Unlikely | Improbable (improbably) - 20-45% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1562.008` | [Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008) | An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment. If an adversary has sufficient permissions, they can disable or modify logging to avoid detection of their activities.  For example, in AWS an adversary may disable CloudWatch/CloudTrail integrations prior to conducting further malicious activity.(Citation: Following the CloudTrail: Generating strong AWS security signals with Sumo Logic) They may alternatively tamper with logging functionality – for example, by removing any associated SNS topics, disabling multi-region logging, or disabling settings that validate and/or encrypt log files.(Citation: AWS Update Trail)(Citation: Pacu Detection Disruption Module) In Office 365, an adversary may disable logging on mail collection activities for specific users by using the `Set-MailboxAuditBypassAssociation` cmdlet, by disabling M365 Advanced Auditing for the user, or by downgrading the user’s license from an Enterprise E5 to an Enterprise E3 license.(Citation: Dark Reading Microsoft 365 Attacks 2021) |
