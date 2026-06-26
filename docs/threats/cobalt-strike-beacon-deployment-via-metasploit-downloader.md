# Cobalt Strike Beacon deployment via Metasploit downloader

## Metadata

- **UUID**: `7c4d9a2e-8f3b-4e6a-9d1c-5a7b8e2f4d3a`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2026-02-09`
- **Modified**: `2026-02-09`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://securelist.com/notepad-supply-chain-attack/115382/](https://securelist.com/notepad-supply-chain-attack/115382/)
- **2**: [https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/](https://www.rapid7.com/blog/post/2026/02/03/notepad-plus-plus-supply-chain-compromise/)

## Description
## Executive Summary

Cobalt Strike Beacon was deployed as the final payload in all three infection chains 
of the Notepad++ supply chain attack, using Metasploit downloader shellcode as the 
delivery mechanism. This represents a sophisticated command and control (C2) 
infrastructure deployment using commercial-grade post-exploitation frameworks.

## Technical Overview

### Deployment Mechanism

Metasploit downloader shellcode is executed as a second-stage payload across multiple 
infection chains. The downloader retrieves Cobalt Strike Beacon from attacker-controlled 
URLs and establishes encrypted C2 communications.

### Beacon Configuration Characteristics

**Encryption**: All Cobalt Strike Beacon configurations are encrypted using XOR 
cipher with the key **"CRAZY"**. This consistent encryption key across multiple 
payloads suggests a common operator or shared infrastructure.

**User-Agent Strings**:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
```

These User-Agent strings mimic legitimate Chrome browser traffic to blend with 
normal network activity.

### Deployment Location

Rapid7 researchers identified Cobalt Strike Beacon deployed to:
```
C:\ProgramData\USOShared\
```

This directory mimics Windows Update service locations (USO = Update Session Orchestrator) 
to evade detection through legitimate-appearing file paths.

## Indicators of Compromise (IOCs)

### Metasploit Downloader URLs

These URLs are used by Metasploit downloader shellcode to retrieve Cobalt Strike Beacon:

```
https://45.77.31[.]210/users/admin
https://cdncheck.it[.]com/users/admin
https://safe-dns.it[.]com/help/Get-Start
https://api.wiresguard[.]com/users/admin
```

**Pattern**: Three of four URLs follow the `/users/admin` pattern, suggesting 
automated generation or templated infrastructure setup.

### Cobalt Strike Beacon C2 URLs

Primary C2 infrastructure identified by Kaspersky:

```
https://45.77.31[.]210/api/update/v1
https://45.77.31[.]210/api/FileUpload/submit
https://cdncheck.it[.]com/api/update/v1
https://cdncheck.it[.]com/api/Metadata/submit
https://cdncheck.it[.]com/api/getInfo/v1
https://cdncheck.it[.]com/api/FileUpload/submit
https://safe-dns.it[.]com/resolve
https://safe-dns.it[.]com/dns-query
https://api.wiresguard[.]com/update/v1
https://api.wiresguard[.]com/api/FileUpload/submit
```

**Pattern Analysis**:
- Multiple C2 URLs use `/api/FileUpload/submit` endpoint
- Several use `/api/update/v1` or similar versioned API patterns
- DNS-themed C2 domains use DNS-related paths (`/resolve`, `/dns-query`)
- API versioning suggests organized infrastructure management

### Additional C2 Infrastructure (Rapid7 Findings)

```
http://59.110.7[.]32:8880/uffhxpSy
http://59.110.7[.]32:8880/api/getBasicInfo/v1
http://124.222.137[.]114:9999/3yZR31VK
http://124.222.137[.]114:9999/api/updateStatus/v1
```

**Key Observations**:
- These use HTTP instead of HTTPS, potentially indicating different operational phases
- Non-standard ports (8880, 9999) for HTTP traffic
- Random path components mixed with API-style paths
- Versioned API endpoints consistent with primary infrastructure

### Malicious Domains

```
cdncheck.it[.]com
safe-dns.it[.]com
wiresguard[.]com (typosquat of wireguard.com)
```

**Domain Strategy**:
- DNS/CDN themed domains for legitimacy
- Typosquatting of legitimate services (WireGuard VPN)
- IT-focused naming to blend with enterprise network traffic

### Malicious IP Addresses

```
45.77.31.210
59.110.7.32
124.222.137.114
```

### Cryptographic Indicators

**XOR Encryption Key**: `CRAZY`

This key is consistently used across multiple Cobalt Strike Beacon configurations, 
serving as a strong indicator of related campaigns or shared infrastructure.

## Attack Flow

1. **Initial Compromise**: Victim system compromised via Notepad++ supply chain attack
2. **Metasploit Downloader Execution**: First-stage payload executes Metasploit downloader shellcode
3. **Beacon Retrieval**: Downloader contacts URLs like `/users/admin` to fetch Cobalt Strike Beacon
4. **Beacon Deployment**: Beacon is written to disk (e.g., `C:\ProgramData\USOShared\`)
5. **C2 Establishment**: Beacon initiates encrypted C2 communications using HTTPS
6. **Persistent Access**: Attacker maintains command and control for espionage or lateral movement

## Infrastructure Commonalities

Analysis reveals consistent patterns across the infrastructure:

1. **URL Patterns**: Frequent use of `/users/admin` for payload delivery
2. **API Design**: Versioned API endpoints (e.g., `/api/update/v1`, `/api/updateStatus/v1`)
3. **File Upload Endpoints**: Multiple C2 servers expose `/api/FileUpload/submit`
4. **Encryption**: Uniform use of XOR with key "CRAZY"
5. **User-Agent**: Consistent Chrome User-Agent strings across campaigns

These similarities indicate:
- Shared infrastructure or operational templates
- Likely common threat actor or coordinated operation
- Professional infrastructure management and organization

## Detection Opportunities

### Network Detection

1. **URL Pattern Matching**:
   - Monitor for HTTP(S) requests to `/users/admin` paths
   - Alert on connections to `/api/FileUpload/submit` endpoints
   - Detect versioned API patterns (`/api/*/v1`)

2. **Domain Reputation**:
   - Block/alert on connections to IOC domains
   - Monitor for typosquat domains of legitimate services
   - Flag DNS-themed domains in non-DNS contexts

3. **SSL/TLS Inspection**:
   - Inspect HTTPS traffic for Cobalt Strike malleable C2 profiles
   - Look for consistent User-Agent patterns
   - Detect encrypted payloads with XOR patterns

4. **Port Usage**:
   - Monitor HTTP traffic on non-standard ports (8880, 9999)

### Host-Based Detection

1. **File System Monitoring**:
   - Alert on file creation in `C:\ProgramData\USOShared\` by non-system processes
   - Monitor for PE files in unusual locations with network activity

2. **Process Monitoring**:
   - Detect Metasploit downloader shellcode execution patterns
   - Monitor for process injection behaviors common to Cobalt Strike
   - Alert on unusual parent-child process relationships

3. **Memory Analysis**:
   - Scan for XOR-encrypted Cobalt Strike configurations in memory
   - Search for the XOR key "CRAZY" in process memory
   - Detect Cobalt Strike reflective DLL injection techniques

4. **Registry Monitoring**:
   - Watch for persistence mechanisms in Run keys or scheduled tasks

### Behavioral Detection

1. **Beaconing Activity**:
   - Detect periodic network connections at regular intervals
   - Monitor for consistent User-Agent strings across multiple connections
   - Identify low-volume, high-frequency HTTPS connections

2. **Data Exfiltration**:
   - Monitor POST requests to `/api/FileUpload/submit` endpoints
   - Alert on large data transfers to external IPs

3. **Lateral Movement**:
   - Detect credential theft attempts (common Cobalt Strike capability)
   - Monitor for lateral movement using SMB, WMI, or PsExec

## MITRE ATT&CK Mapping

### T1071.001 - Application Layer Protocol: Web Protocols

Cobalt Strike Beacon uses HTTPS/HTTP for C2 communications to blend with legitimate 
web traffic. The use of standard ports (443, 80) and Chrome User-Agents mimics 
normal browser behavior.

### T1573.001 - Encrypted Channel: Symmetric Cryptography

Beacon configurations are encrypted using XOR cipher with the key "CRAZY". 
Additionally, HTTPS provides transport layer encryption for C2 communications.

### T1105 - Ingress Tool Transfer

Metasploit downloader fetches Cobalt Strike Beacon from remote URLs, transferring 
the post-exploitation framework to the compromised system.

### T1059 - Command and Scripting Interpreter

Cobalt Strike Beacon provides interactive command execution capabilities, allowing 
operators to execute commands and scripts on compromised systems.

## Mitigation Recommendations

### Immediate Actions

1. **Network Blocking**:
   - Block all IOC IPs and domains at firewall/proxy level
   - Implement DNS sinkholing for malicious domains

2. **Threat Hunting**:
   - Search for files in `C:\ProgramData\USOShared\` created by non-system processes
   - Hunt for network connections to IOC infrastructure
   - Scan memory for XOR key "CRAZY" or Cobalt Strike artifacts

3. **Endpoint Isolation**:
   - Isolate systems showing signs of Cobalt Strike infection
   - Prevent lateral movement through network segmentation

### Long-Term Measures

1. **EDR Deployment**:
   - Deploy EDR solutions with Cobalt Strike detection capabilities
   - Enable memory scanning and behavioral detection

2. **Network Monitoring**:
   - Implement SSL/TLS inspection for encrypted traffic
   - Deploy IDS/IPS rules for Cobalt Strike indicators
   - Monitor for beaconing behavior patterns

3. **Application Control**:
   - Implement application whitelisting to prevent unauthorized executables
   - Block execution from non-standard directories like `C:\ProgramData\USOShared\`

4. **Supply Chain Security**:
   - Verify software update integrity through code signing
   - Restrict software installation to official channels only

5. **User Education**:
   - Train users on supply chain attack risks
   - Educate on identifying suspicious system behavior

## Threat Actor Assessment

The consistent infrastructure patterns, encryption keys, and professional operational 
security suggest a coordinated threat actor or shared infrastructure among related 
groups. The targeting of government and financial sectors across multiple countries 
indicates espionage or financial crime motivations.

**Sophistication Level**: High
- Use of commercial-grade post-exploitation framework (Cobalt Strike)
- Organized C2 infrastructure with versioned APIs
- Persistent operations across multiple months
- Supply chain compromise capabilities

**Operational Security**:
- HTTPS encryption for C2 traffic
- Legitimate-appearing domain names and URL paths
- Mimicking Windows system directories for file placement
- Use of common User-Agent strings

## Conclusion

The deployment of Cobalt Strike Beacon via Metasploit downloader represents a 
critical threat to organizations worldwide. The consistent use of specific encryption 
keys, infrastructure patterns, and professional tradecraft indicates an organized 
and persistent adversary. Organizations should prioritize detection and mitigation 
efforts focusing on the specific IOCs and behavioral patterns identified in this 
threat vector.

Immediate action is required to:
1. Detect existing infections through IOC sweeps
2. Block C2 communications through network controls
3. Hunt for artifacts in memory and on disk
4. Implement long-term defenses against post-exploitation frameworks

This threat vector should be considered **CRITICAL** priority for incident response 
and threat hunting operations.

## Criticality
**Severe** - A Severe priority incident is likely to result in a significant impact to public health or safety, national security, economic security, foreign relations, or civil liberties.

## Terrain
> **Windows workstations and laptops, particularly developer environments, that have 
been compromised through the Notepad++ supply chain attack. The Metasploit 
downloader acts as a second-stage payload fetching mechanism, downloading and 
executing Cobalt Strike Beacon from attacker-controlled infrastructure. This 
affects organizations across government, financial services, and IT sectors 
in multiple countries including Vietnam, El Salvador, Australia, and the Philippines.

Surface: OS::Windows::Desktop**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Highly significant incident | A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy. |
| Impact | Data Breach; Business disruption; Reputational Damages; Legal and regulatory; Monetary Loss | - |
| Leverage | Elevation of privilege; Information Disclosure; Software installation | - |
| Viability | Almost certain | Nearly certain - 95-99% |
| Kill Chain | Command & Control | Techniques that allow attackers to communicate with controlled systems within a target network. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1071.001` | [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001) | Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.   Protocols such as HTTP/S(Citation: CrowdStrike Putter Panda) and WebSocket(Citation: Brazking-Websockets) that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. |
| `T1573.001` | [Encrypted Channel: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001) | Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4. |
| `T1105` | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)).   On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, [certutil](https://attack.mitre.org/software/S0160), and [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.(Citation: t1105_lolbas)  A number of these tools, such as `wget`, `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor may attempt to verify its integrity by checking its hash value (e.g., via `certutil -hashfile`).(Citation: Google Cloud Threat Intelligence COSCMICENERGY 2023)  Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts. Adversaries have also abused file application features, such as the Windows `search-ms` protocol handler, to deliver malicious files to victims through remote file searches invoked by [User Execution](https://attack.mitre.org/techniques/T1204) (typically after interacting with [Phishing](https://attack.mitre.org/techniques/T1566) lures).(Citation: T1105: Trellix_search-ms)  Files can also be transferred using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well as native or otherwise present tools on the victim system.(Citation: PTSecurity Cobalt Dec 2016) In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.(Citation: Dropbox Malware Sync) |
| `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).  There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).  Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python) |

## Chaining
```mermaid
flowchart LR
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a["Cobalt Strike Beacon deployment via Metasploit downloader"]
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22["Notepad++ supply chain attack"]
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|atomicity::implements| 8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22
```
### Chaining details
#### implements -> Notepad++ supply chain attack (`atomicity::implements`)
This threat vector represents the final stage payload deployment mechanism 
used across all three infection chains of the Notepad++ supply chain attack. 
Metasploit downloader shellcode retrieves and deploys Cobalt Strike Beacon 
to establish persistent command and control infrastructure.

- **Target UUID**: `8b7cae6f-b6cf-4414-9cdc-fe8c8ee7ee22`

## Relations
```mermaid
flowchart TB
subgraph "Objective"
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d["Detect Notepad++ Supply Chain Compromise Activity"]
end
subgraph "Signal"
2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c["2f7c9b4e-8d3a-4e6f-9b1c-7a5d8e2f4b6c"]
4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d["4e7b9d3f-6c2a-4e8f-9b1d-7a5c8e3f6b2d"]
6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d["6c9f3e7b-4d2a-4e8f-9b6d-3a7c5e1f8b4d"]
8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d["8d4f6b2e-9c7a-4e1f-8b3d-6a9c5e7f2b4d"]
9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d["9b6e4d8f-7c3a-4e2f-8b1d-6a9c5e7f3b4d"]
end
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a["Cobalt Strike Beacon deployment via Metasploit downloader"]
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|objective| 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|signal| 2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|signal| 4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|signal| 6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|signal| 8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d
7c4d9a2e_8f3b_4e6a_9d1c_5a7b8e2f4d3a -->|signal| 9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d
```
