# Web Path Traversal Attack

## Metadata

- **UUID**: `b330d3a8-1783-4210-9fec-11e6ecfe135e`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2022-09-01`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- **2**: [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)

## Description
Directory traversal (also known as file path traversal) is a web security
vulnerability that allows an attacker to read arbitrary files on the server
that is running an application. 

By manipulating variables that reference files with “dot-dot-slash (../)”
sequences and its variations or by using absolute file paths, it may be
possible to access arbitrary files and directories stored on file system
including application source code or configuration and critical system files.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A web application vulnerable to path traversal, i.e. which does not
sanitize user inputs sufficiently and with unsufficient resource access
policy.

Domains: Enterprise, Public Cloud, Private Cloud, Networking
Targets: Web Application Servers
Platforms: Windows, Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Identity Theft | - |
| Leverage | Information Disclosure; Modify configuration; Modify data | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Discovery | Techniques that allow an attacker to gain knowledge about a system and its network environment. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1083` | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) | Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.  Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather file and directory information (e.g. <code>dir</code>, <code>show flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)  Some files and directories may require elevated or specific user permissions to access. |
