# User information gathering in Linux systems

## Metadata

- **UUID**: `8bc82ff8-e106-4377-98f1-2cb912631ffa`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-08-07`
- **Modified**: `2025-08-12`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.tecmint.com/check-user-in-linux](https://www.tecmint.com/check-user-in-linux)
- **2**: [https://docs.rtlcopymemory.com/privilege-escalation/linux-privilege-escalation/information-gathering](https://docs.rtlcopymemory.com/privilege-escalation/linux-privilege-escalation/information-gathering)
- **3**: [https://medium.com/@velmuruganofficial/top-15-advanced-and-best-information-gathering-tools-67f07550e502](https://medium.com/@velmuruganofficial/top-15-advanced-and-best-information-gathering-tools-67f07550e502)
- **4**: [https://linuxsimply.com/getent-command-in-linux/](https://linuxsimply.com/getent-command-in-linux/)
- **5**: [https://www.geeksforgeeks.org/linux-unix/getent-command-in-linux-with-examples](https://www.geeksforgeeks.org/linux-unix/getent-command-in-linux-with-examples)
- **6**: [https://www.man7.org/linux/man-pages/man8/lastlog.8.html](https://www.man7.org/linux/man-pages/man8/lastlog.8.html)
- **7**: [https://www.cyberciti.biz/faq/faillog-in-linux-command](https://www.cyberciti.biz/faq/faillog-in-linux-command)

## Description
Threat actors use various methods and tools to collect user data on Linux
systems. Some of them are given below.

### Common methods used for gathering of user's information on Linux

Examples:

- Current user: for reconnaissance purposes on a Linux system threat actors
  are using commands like `whoami` to retrieve the current username running
  on the system. Threat actors can use and `lslogins` to list an information
  about known users in the system, which typically includes details such as
  the username, UID (User ID), GID (Group ID), home directory, shell, last
  login time, and more, depending on the options used and the system
  configuration ref [1].  
- User list: a threat actor group can use a `getent` command with an option
  `passwd` or `cat /etc/passwd` command to retrieve a list of all users on
  the system ref [1].
- User ID and group ID: the `id` command can be used to retrieve the user ID
  and a group ID of the current user ref [2].
- Group list: a command `groups` <group_name> can be used in Linux to view
  user's group membership. Or with other command `getent group` or cat
  `/etc/group` thereat actors can retrieve a list of all groups on the
  system ref [1],[4].  
- Other user's information: commands like `who` can show an information for
  the current logged-in user. A threat actor may use and `users` command
  to display the list of currently logged-in users on the Linux system
  ref [1].
- Linux user's activity: `w` coomand executed on Linux shows the current
  logged users activity on the system ref [1]. 
- User shell: a threat actor may run the command `getent passwd <username>`
  to retrieve the user's shell. The command output lists the user details
  from the 'passwd' database, including the username, user ID, group ID,
  home directory, and default shell ref [5].  
- Last login: an adversary can use the `lastlog` command to retrieve
  information about the last user's login ref [6]. 
- Failed login attempts: with the `faillog` command a threat actor may
  retrieve information about failed login attempts ref [7].

### Some of the known tools used for Linux user's information collection

- `Metasploit`: A penetration testing framework that includes tools for
  collecting user data and exploiting vulnerabilities.
- `Linux.Ekoms`: This is a custom tool that can collect user data, including
  login credentials and credit card numbers.
- `Linux.Mumblehard`: it's a malware that collects user data and uses it for
  spamming and phishing campaigns.
- `TsarSapphire`: This utility can collect user data, including login
  credentials and sensitive information.
- `Remaiten`: A payload for Linux which collects user data and uses it for
  malicious activities.
- `Kaiten`: A Linux malware that collects user data and potentially can use
  it further for distributed denial-of-service (DDoS) attacks.
- `Linux.Keylogger`: A keylogger that collects user keystrokes, including
  login credentials and sensitive information.
- `Mayhem`: This is a malware that can collect user data on Linux, including
  login credentials and sensitive information, and uses it for malicious
  activities.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires an initial access to a Linux system with sufficient
rights to execute commands.

Domains: Enterprise
Targets: End-user, Customer
Platforms: Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Data Breach | Non-public information has been accessed from the outside, and successfully extracted. |
| Leverage | Information Disclosure | Threat action intending to read a file that one was not granted access to, or to read data in transit. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Reconnaissance | Researching, identifying and selecting targets using active or passive reconnaissance. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1589` | [Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589) | Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations.  Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about users could also be enumerated via other active means (i.e. [Active Scanning](https://attack.mitre.org/techniques/T1595)) such as probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA /methods associated with those usernames.(Citation: GrimBlog UsernameEnum)(Citation: Obsidian SSPR Abuse 2023) Information about victims may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: OPM Leak)(Citation: Register Deloitte)(Citation: Register Uber)(Citation: Detectify Slack Tokens)(Citation: Forbes GitHub Creds)(Citation: GitHub truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks)  Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)). |

## Chaining
```mermaid
flowchart LR
8bc82ff8_e106_4377_98f1_2cb912631ffa["User information gathering in Linux systems"]
3b1026c6_7d04_4b91_ba6f_abc68e993616["Abusing Lolbins to Enumerate Local and Domain Accounts and Groups"]
e2d8ce6b_f21e_4444_a828_0c6b722a9c93["Local user account added"]
8bc82ff8_e106_4377_98f1_2cb912631ffa -->|sequence::succeeds| 3b1026c6_7d04_4b91_ba6f_abc68e993616
3b1026c6_7d04_4b91_ba6f_abc68e993616 -->|sequence::succeeds| e2d8ce6b_f21e_4444_a828_0c6b722a9c93
```
### Chaining details
#### succeeds -> Abusing Lolbins to Enumerate Local and Domain Accounts and Groups (`sequence::succeeds`)
The threat actors may attempt to enumerate the environment using some
Lolbins on a local system, domain accounts or groups to gather
information for the users in the enviornoment.

- **Target UUID**: `3b1026c6-7d04-4b91-ba6f-abc68e993616`
#### succeeds -> Local user account added (`sequence::succeeds`)
An adversary can use post-exploittaion techniques. For example, when a
set of usernames is collected initally, after that the threat actor can
use these names and data for further steps like add a local account to
the system for persistence.

- **Target UUID**: `e2d8ce6b-f21e-4444-a828-0c6b722a9c93`
