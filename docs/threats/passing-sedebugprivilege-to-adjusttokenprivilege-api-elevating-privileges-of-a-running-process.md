# Passing SeDebugPrivilege to AdjustTokenPrivilege API elevating privileges of a running process

## Metadata

- **UUID**: `5d373113-18f9-41bb-bdde-3abbfa53cb86`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-11-16`
- **Modified**: `2022-11-17`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://blog.malwarebytes.com/threat-analysis/2021/06/kimsuky-apt-continues-to-target-south-korean-government-using-appleseed-backdoor/](https://blog.malwarebytes.com/threat-analysis/2021/06/kimsuky-apt-continues-to-target-south-korean-government-using-appleseed-backdoor/)
- **2**: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)
- **3**: [https://pentestlab.blog/2017/04/03/token-manipulation/](https://pentestlab.blog/2017/04/03/token-manipulation/)
- **4**: [https://adsecurity.org/?page_id=1821#TOKENElevate](https://adsecurity.org/?page_id=1821#TOKENElevate)
- **5**: [https://juggernaut-sec.com/dumping-credentials-mimikatz-lsa-dump/](https://juggernaut-sec.com/dumping-credentials-mimikatz-lsa-dump/)
- **6**: [https://attack.mitre.org/techniques/T1134/001/](https://attack.mitre.org/techniques/T1134/001/)
- **7**: [https://docs.rapid7.com/metasploit/meterpreter-getsystem/](https://docs.rapid7.com/metasploit/meterpreter-getsystem/)
- **8**: [https://www.mcafee.com/enterprise/en-us/assets/reports/rp-cuba-ransomware.pdf](https://www.mcafee.com/enterprise/en-us/assets/reports/rp-cuba-ransomware.pdf)
- **9**: [https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)

## Description
A threat actor can attempt to escalate privileges from a user or 
administrator context to NT SYSTEM by using the SeDebugPrivilege to adjust 
the memory of running process with a call to the AdjustTokenPrivilege API. 
This method uses built-in Windows APIs and commands to escalate privileges 
by changing the privileges of the running process in-memory. See Palantir 
reference. 

The intention of access token impersonation/theft is to grant a process the 
same permissions as another running process with a specific context, often 
NT SYSTEM. This may increase the capabilities of the now-elevated process 
or reduce its probability of detection.

For access token impersonation an adversary can use standard command-line 
shell to initiate 'runas' commands or to use payloads that call Windows 
token APIs directly. The changes in Windows API calls can manipulate 
access tokens for further account access and malicious purposes.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **On an already compromised Windows endpoint in a user or administrator 
context that has SeDebugPrivilege assigned (rarely on user context). 
Windows servers and windows workstations/laptops - anything 
Windows.

Domains: Enterprise, Public Cloud, Private Cloud
Targets: Auth token, Workstations, Windows API, Control Server, Web Application Servers, Public-Facing Servers
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement; Data Breach | - |
| Leverage | Elevation of privilege; Modify privileges; Spoofing | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1134.001` | [Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) | Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using `DuplicateToken` or `DuplicateTokenEx`.(Citation: DuplicateToken function) The token can then be used with `ImpersonateLoggedOnUser` to allow the calling thread to impersonate a logged on user's security context, or with `SetThreadToken` to assign the impersonated token to a thread.  An adversary may perform [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) when they have a specific, existing process they want to assign the duplicated token to. For example, this may be useful for when the target user has a non-network logon session on the system.  When an adversary would instead use a duplicated token to create a new process rather than attaching to an existing process, they can additionally [Create Process with Token](https://attack.mitre.org/techniques/T1134/002) using `CreateProcessWithTokenW` or `CreateProcessAsUserW`. [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) is also distinct from [Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) in that it refers to duplicating an existing token, rather than creating a new one. |
