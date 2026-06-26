# Usage of CrackMapExec module Masky on compromised endpoint

## Metadata

- **UUID**: `9d4658ad-d4d5-4f3c-990f-bb486edd47f4`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-10-28`
- **Modified**: `2022-10-28`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://z4ksec.github.io/posts/masky-release-v0.0.3/#detection-vectors](https://z4ksec.github.io/posts/masky-release-v0.0.3/#detection-vectors)
- **2**: [https://twitter.com/mpgn_x64/status/1584863925744521216](https://twitter.com/mpgn_x64/status/1584863925744521216)
- **3**: [https://github.com/Porchetta-Industries/CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
- **4**: [https://github.com/maaaaz/CrackMapExecWin](https://github.com/maaaaz/CrackMapExecWin)
- **5**: [https://wiki.porchetta.industries/](https://wiki.porchetta.industries/)
- **6**: [https://attack.mitre.org/software/S0488/](https://attack.mitre.org/software/S0488/)

## Description
CrackMapExec is a post-compromise tool that contains a number of
modules and functionalities that allow red teams, pentesters and
threat actors to perform post-compromise actions. Detecting
both the presence of the tool itself, plus the usage of the tool
is an important baseline security detection.

Masky is a python library providing an alternative way to remotely
dump domain users’ credentials thanks to an ADCS. A 
command line tool has been built on top of this library in order to
easily harvest PFX, NT hashes and TGT on a larger 
scope.

This tool does not exploit any new vulnerability and does not work by
dumping the LSASS process memory. Indeed, it 
only takes advantage of legitimate Windows and Active Directory features
(token impersonation, certificate 
authentication via kerberos and NT hashes retrieval via PKINIT).

Masky is a new module, which in certain ways is less noisy than
dumping LSASS, but if AD CS CAs have auditing enabled, will be
very noisy and detectable.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **On a compromised Windows or Linux variant endpoint, Masky can be used to collect the NT hash for all connected users

Domains: Enterprise, Public Cloud
Targets: Virtual Machines, Workstations
Platforms: Windows, Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement; Business disruption; Competitive disadvantage; Data Breach; Reputational Damages; Legal and regulatory; Monetary Loss; Nuisance | - |
| Leverage | Elevation of privilege; Spoofing | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |
