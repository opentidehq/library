# Collecting sensitive information via custom script extensions

## Metadata

- **UUID**: `b954303c-0ad0-4dc0-b5ca-492c3de9cd53`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-06-11`
- **Modified**: `2025-06-11`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows)
- **2**: [https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-azure-with-custom-script-extensions/](https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-azure-with-custom-script-extensions/)
- **3**: [https://blog.devsecopsguides.com/p/attacking-azure](https://blog.devsecopsguides.com/p/attacking-azure)
- **4**: [https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-linux](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-linux)

## Description
Custom Script Extensions in Azure are powerful automation tools for configuring 
and managing Virtual Machines (VMs). However, attackers can exploit these extensions 
to collect sensitive information in a variety of ways.

## Credential Harvesting
- **Stored Credentials:** Attackers deploy scripts that search for credentials stored 
in plaintext files, configuration files, or environment variables.
- **Credential Managers:** Scripts can target credential managers or vaults such 
as Azure Key Vault, Windows Credential Manager, or third-party vaults to extract 
stored credentials.

## Configuration Files and Secrets
- **Configuration Files:** Scripts can systematically search for and exfiltrate 
configuration files containing sensitive data like database connection strings, 
API keys, or other secrets.
- **Environment Variables:** Attackers can extract environment variables that hold 
sensitive configuration or authentication information.

## Log Files and Audit Trails
- **Log Files:** Scripts can access and exfiltrate log files that may contain sensitive 
information, such as authentication logs, database logs, or application logs.
- **Audit Trails:** Attackers can collect and exfiltrate audit trails that record 
administrative actions or other sensitive activities.

## Memory Scraping
- **Running Processes:** Scripts can be designed to scrape memory from running processes 
to extract sensitive information like session tokens, encryption keys, or other 
in-memory data.
- **DLL Injection:** Attackers can use DLL injection techniques within scripts to 
extract sensitive data from running processes.

## Network Traffic Interception
- **Network Sniffing:** Scripts can enable network sniffing tools to capture sensitive 
information transmitted over the network.
- **Proxy Servers:** Attackers can configure proxy servers via scripts to intercept 
and log network traffic, capturing sensitive data in transit.

## Exploitation of Vulnerabilities
- **Unpatched Software:** Attackers can exploit vulnerabilities in unpatched software 
to gain elevated privileges and execute scripts that collect sensitive information.
- **Misconfigurations:** Misconfigurations in the VM or the environment can be exploited 
to deploy and run malicious scripts.

## Data Exfiltration Channels
- **External Storage:** Scripts can exfiltrate collected data to external storage 
solutions such as Azure Blob Storage, external servers, or other cloud storage services.
- **Email Exfiltration:** Attackers can use scripts to send sensitive information 
via email to an external address.
- **Command and Control (C2) Servers:** Scripts can communicate with C2 servers 
to exfiltrate data and receive further instructions.

## Persistent Data Collection
- **Scheduled Tasks:** Attackers can create scheduled tasks or services that periodically 
execute scripts to collect and exfiltrate sensitive information over time.
- **Backdoor Scripts:** Scripts can be designed to act as backdoors, allowing attackers 
to execute commands and collect data as needed.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Attackers need to gain access to an Azure account with the Virtual Machine Contributor 
role (or equivalent) can use custom script extensions to execute arbitrary code 
as SYSTEM or root on VMs.

Domains: Public Cloud, Private Cloud, Enterprise
Targets: Cloud Storage Accounts, Key Store, Virtual Machines, Serverless, API Endpoints, Cloud Portal, Relational Database, NoSQL Database, Software Containers
Platforms: Azure, Windows, Linux, Azure AD, Blob Storage**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Monetary Loss; Business disruption | - |
| Leverage | Information Disclosure; Elevation of privilege; Tampering; Repudiation; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).  There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).  Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python) |
| `T1651` | [Cloud Administration Command](https://attack.mitre.org/techniques/T1651) | Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents. (Citation: AWS Systems Manager Run Command)(Citation: Microsoft Run Command)  If an adversary gains administrative access to a cloud environment, they may be able to abuse cloud management services to execute commands in the environment’s virtual machines. Additionally, an adversary that compromises a service provider or delegated administrator account may similarly be able to leverage a [Trusted Relationship](https://attack.mitre.org/techniques/T1199) to execute commands in connected virtual machines.(Citation: MSTIC Nobelium Oct 2021) |
| `T1119` | [Automated Collection](https://attack.mitre.org/techniques/T1119) | Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals.   In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data.(Citation: Mandiant UNC3944 SMS Phishing 2023)   This functionality could also be built into remote access tools.   This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) to identify and move files, as well as [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538) and [Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) to identify resources in cloud environments. |
