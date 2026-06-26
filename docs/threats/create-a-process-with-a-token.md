# Create a process with a token

## Metadata

- **UUID**: `54adba8e-e3f8-43e2-bcd5-7c3cd61112d9`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-08-04`
- **Modified**: `2022-08-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)
- **2**: [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11))

## Description
Adversaries may create a new process with a different token 
to escalate privileges and bypass access controls. A processes 
can be created with the token and resulting security context 
of another user using features such as CreateProcessWithTokenW 
and runas.

An adversary creates a new access token with DuplicateToken(Ex) 
and uses it with CreateProcessWithTokenW to create a new process 
running under the security context of the impersonated user. 
This is useful for creating a new process under the security 
context of a different user.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **The victim Window endpoints need to have vulnerable accounts with 
misconfigured settings that may leak access tokens.

Domains: Enterprise
Targets: Auth token, Remote access, Identity Services
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft; Impairement | - |
| Leverage | Elevation of privilege; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1134.002` | [Access Token Manipulation: Create Process with Token](https://attack.mitre.org/techniques/T1134/002) | Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as <code>CreateProcessWithTokenW</code> and <code>runas</code>.(Citation: Microsoft RunAs)  Creating processes with a token not associated with the current user may require the credentials of the target user, specific privileges to impersonate that user, or access to the token to be used. For example, the token could be duplicated via [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) or created via [Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) before being used to create a process.  While this technique is distinct from [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001), the techniques can be used in conjunction where a token is duplicated and then used to create a new process. |
