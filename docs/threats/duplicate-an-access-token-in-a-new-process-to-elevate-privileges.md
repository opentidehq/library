# Duplicate an access token in a new process to elevate privileges

## Metadata

- **UUID**: `349348ca-66f5-41d2-8610-6bb61556d773`
- **Schema**: `threat::1.0`
- **Version**: `4`
- **Created**: `2022-11-18`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)
- **2**: [https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- **3**: [https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/untitled-1/create-process-with-token](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/untitled-1/create-process-with-token)

## Description
An adversary can use automated solutions like CobaltStrike framework
to create a new process with a duplicated token to escalate privileges 
and bypass access controls. An adversary can duplicate a desired access 
token with DuplicateToken(Ex) and use it with CreateProcessWithTokenW 
to create a new process running under the security context of the 
impersonated user. This is useful for creating a new process under 
the security context of a different user.

The new process runs in the security context of the specified token. 
It can optionally load the user profile for the specified user.
Usually the function CreateProcessWithTokenW is running like 
a process winbase.h 

The process that calls CreateProcessWithTokenW must have 
SE_IMPERSONATE_NAME privilege. 

Adversaries commonly use token stealing to elevate their security context 
from the administrator level to the SYSTEM level. An adversary can use a 
token to authenticate to a remote system as the account for that token if the 
account has appropriate permissions on the remote system.

Example for spawn of a process with token duplication:
The process spawn is usually with PID (Process Identifier): 2572

spawn windows/beacon_https/reverse_https (<ip_address>:443) 
in a high integrity process (token duplication)

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actors are using already compromised Windows environment to create 
a new process with a duplicated token. Their purpose is often to elevate 
their privileges to SYSTEM level access (NT AUTHORITY\SYSTEM), but the same 
threat vector can also be used for defense evasion and other purposes by 
duplicating other access token types and privilege levels.

Domains: Enterprise, Public Cloud
Targets: Auth token, Control Server, Desktop, Laptop
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft | Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships. |
| Leverage | Elevation of privilege | Capacity to augment leverage over the target system by upgrading the compromised access rights |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1134.002` | [Access Token Manipulation: Create Process with Token](https://attack.mitre.org/techniques/T1134/002) | Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as <code>CreateProcessWithTokenW</code> and <code>runas</code>.(Citation: Microsoft RunAs)  Creating processes with a token not associated with the current user may require the credentials of the target user, specific privileges to impersonate that user, or access to the token to be used. For example, the token could be duplicated via [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) or created via [Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) before being used to create a process.  While this technique is distinct from [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001), the techniques can be used in conjunction where a token is duplicated and then used to create a new process. |
