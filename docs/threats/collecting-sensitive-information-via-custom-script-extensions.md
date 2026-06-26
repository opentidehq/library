# Collecting sensitive information via custom script extensions

## Metadata

- **UUID**: `b954303c-0ad0-4dc0-b5ca-492c3de9cd53`
- **Schema**: `threat::1.0`
- **TLP**: clear

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

## Techniques
- T1059
- T1651
- T1119
