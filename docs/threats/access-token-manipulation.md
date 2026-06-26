# Access token manipulation

## Metadata

- **UUID**: `2404055a-10f8-4c50-9e9b-0f26756e7838`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-02-03`
- **Modified**: `2025-02-03`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-059a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-059a)
- **2**: [https://www.manageengine.com/log-management/cyber-security/account-manipulation-attack.html](https://www.manageengine.com/log-management/cyber-security/account-manipulation-attack.html)
- **3**: [https://www.elastic.co/blog/how-attackers-abuse-access-token-manipulation](https://www.elastic.co/blog/how-attackers-abuse-access-token-manipulation)

## Description
### Access token:

An access token is part of the logon session of the user, and it also contains their credentials for
Windows single sign on (SSO) authentication to access local or remote network services.

When a user signs on to a machine ((irrespective of the logon type), the system generates an 
access token for them. With this access token, Windows handles the user identification,
security, and access rights on the system.

### Access token manipulation:

An attacker can manipulate access tokens to make a process appear to be initiated by a different
user account, when in reality, the request was originated by the account of the attacker.

Attackers use access tokens to escalate privileges from administrative to SYSTEM level,
allowing them to undertake malicious operations and remotely access systems in the corporate network.

### Manipulating access token by injecting malware:

- If the current logged-on user on the compromised or infected machine is a member of the administrator
  group of users or is running a process with higher privileges (e.g., by using the “runas” command),
  malware can take advantage of the privileges of the process’s access token to elevate its privileges
  on the system, allowing it to perform privileged tasks.

- Malware can enumerate the Windows processes running with higher privileges (typically SYSTEM level privileges),
  obtain the access tokens for those processes, and utilise the acquired token to launch new processes.
  As a result, the new process is launched in the context of the SYSTEM user, as represented by the token.

- Malware can also perform a token impersonation attack, in which it copies the access tokens of higher-level
  SYSTEM processes, converts them into impersonation tokens using appropriate Windows functionality, 
  and then impersonates the SYSTEM user on the infected machine, thereby elevating its privileges.

### Methods used to manipulate access tokens:  

- Theft of access tokens.
  An attacker can copy and use existing tokens from other processes to undertake malicious activities using 
  the built-in Windows API functions:
    - To make duplicate tokens of existing access tokens, utilise the DuplicateTokenEx() function.
    - The ImpersonateLoggedOnUser() function is used to run the process as another user.
    - Attackers can assign an impersonated token to a thread using the SetThreatToken() function.

- Using a stolen access token to create a new process.
  Use the CreateProcessWithTokenW() function to create a new process with a duplicated token. The attackers
  can use this function to generate tokens that implement the security context of any user they want to impersonate.

- Creating Logon sessions.
  If an attacker has the credentials for any user account, they can use the LogonUser() function to create logon 
  sessions for them remotely. They can then gain a token from the security context of the logged in user, 
  which they can give to a thread to launch a process.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversary must have administrative privileges on Windows systems within 
 the enterprise network.

Domains: Enterprise
Targets: Laptop, Workstations
Platforms: Active Directory, Windows, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Business disruption; Reputational Damages; Operating costs | - |
| Leverage | Modify configuration; Modify data; Tampering; New Accounts | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] HAFNIUM](https://attack.mitre.org/groups/G0125) | `att&ck::G0125` | ('att&ck',) | [HAFNIUM](https://attack.mitre.org/groups/G0125) is a likely state-sponsored cyber espionage group operating out of China that has been active since at least January 2021. [HAFNIUM](https://attack.mitre.org/groups/G0125) primarily targets entities in the US across a number of industry sectors, including infectious disease researchers, law firms, higher education institutions, defense contractors, policy think tanks, and NGOs. [HAFNIUM](https://attack.mitre.org/groups/G0125) has targeted remote management tools and cloud software for intial access and has demonstrated an ability to quickly operationalize exploits for identified vulnerabilities in edge devices.(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)(Citation: Microsoft Silk Typhoon MAR 2025) |
| [[Enterprise] Lazarus Group](https://attack.mitre.org/groups/G0032) | `att&ck::G0032` | ('att&ck',) | [Lazarus Group](https://attack.mitre.org/groups/G0032) is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.(Citation: US-CERT HIDDEN COBRA June 2017)(Citation: Treasury North Korean Cyber Groups September 2019) The group has been active since at least 2009 and was reportedly responsible for the November 2014 destructive wiper attack against Sony Pictures Entertainment as part of a campaign named Operation Blockbuster by Novetta. Malware used by [Lazarus Group](https://attack.mitre.org/groups/G0032) correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.(Citation: Novetta Blockbuster)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups, such as [Andariel](https://attack.mitre.org/groups/G0138), [APT37](https://attack.mitre.org/groups/G0067), [APT38](https://attack.mitre.org/groups/G0082), and [Kimsuky](https://attack.mitre.org/groups/G0094). |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1098` | [Account Manipulation](https://attack.mitre.org/techniques/T1098) | Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.(Citation: FireEye SMOKEDHAM June 2021) These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.   In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078). |
