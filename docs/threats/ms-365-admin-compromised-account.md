# MS 365 admin compromised account

## Metadata

- **UUID**: `20bd3620-b13b-4895-b291-b1a26bd9aef3`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Compromised credentials may be used to bypass access controls placed on various resources on systems
within the network and may even be used for persistent access to remote systems and externally
available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.

Compromised credentials may also grant an adversary increased privilege to specific systems or access
to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction
with the legitimate access those credentials provide to make it harder to detect their presence.

There are several methods used by adversaries to compromise valid accounts, such as:  

- Phishing attacks (Spear Phishing, Whaling, BEC).  
- Password guessing and cracking (Credential stuffing, Bruteforce, Password spraying, exploiting weak passwords).
- OAuth and API Abuse.
- Exploiting vulnerabilities in third-party software.

## Techniques
- T1078
- T1566
