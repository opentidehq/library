# Switching off forced signed commits for GitHub repository

## Metadata

- **UUID**: `cd1baed8-3ea8-42e1-a27d-9da9ddb2f5b8`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-11-28`
- **Modified**: `2022-11-28`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
- **2**: [https://github.com/github/safe-settings](https://github.com/github/safe-settings)
- **3**: [https://www.gpg4win.org/](https://www.gpg4win.org/)

## Description
Development and DevOps teams may turn on signed commits to ensure that an 
attacker cannot commit code to a code repository of an organization by 
merely succesfully stealing an OAuth token of a developer. With forced 
commits, the attacker will be blocked from committing code changes to a
repository, essentially limiting the attacker from attaining lateral 
movement or similar objectives, unless the attacker turns off the forced 
commit policy.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires a GitHub organization, either as SaaS or as an on-prem GitHub 
instance. Attacker requires admin credentials to change the setting or 
an exploit to bypass authentication or similar.

Domains: SaaS, Enterprise
Targets: Cloud Portal, Code Repositories, CI/CD Pipelines, Control Server
Platforms: Github**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Localised incident | A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation. |
| Impact | Impairement | Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery. |
| Leverage | Dwelling; Infrastructure Compromise; Modify configuration | - |
| Viability | Unlikely | Improbable (improbably) - 20-45% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1562` | [Impair Defenses](https://attack.mitre.org/techniques/T1562) | Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.  Adversaries may also impair routine operations that contribute to defensive hygiene, such as blocking users from logging out, preventing a system from shutting down, or disabling or modifying the update process. Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components. These restrictions can further enable malicious operations as well as the continued propagation of incidents.(Citation: Google Cloud Mandiant UNC3886 2024)(Citation: Emotet shutdown) |
