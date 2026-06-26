# Grager backdoor

## Metadata

- **UUID**: `662af2da-7017-4899-88fc-e77617a15130`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2024-10-16`
- **Modified**: `2024-10-16`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.security.com/threat-intelligence/cloud-espionage-attacks](https://www.security.com/threat-intelligence/cloud-espionage-attacks)
- **2**: [https://www.csoonline.com/article/3483919/apt-groups-increasingly-attacking-cloud-services-to-gain-command-and-control.html](https://www.csoonline.com/article/3483919/apt-groups-increasingly-attacking-cloud-services-to-gain-command-and-control.html)
- **3**: [https://candid.technology/unc5330-gogra-trojan-onedrive-google-drive-micorosft-mail/](https://candid.technology/unc5330-gogra-trojan-onedrive-google-drive-micorosft-mail/)
- **4**: [https://cloud.google.com/blog/topics/threat-intelligence/ivanti-post-exploitation-lateral-movement](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-post-exploitation-lateral-movement)

## Description
A previously unseen backdoor named Grager was deployed against three
organizations in the past - Taiwan, Hong Kong, and Vietnam in April
2024. Trojan.Grager is a second APT malware implant leveraging the
Microsoft Graph API from a multi-step malware campaign abusing
cloud services ref [1, 2].  

The analysis of the backdoor revealed that it used the Graph
API to communicate with a C&C server hosted on Microsoft OneDrive.
Grager was downloaded from a typosquatted URL mimicking an open-
source file archiver 7-Zip (7 zip .msi file) ref [1].  

The .msi dropper, is a Trojanized 7-Zip installer that installs
the real 7-Zip software into the Windows Program Files folder
(C:\Program Files (x86)\7-Zip) along with a malicious DLL named
`epdevmgr.dll`, a copy of the Tonerjam malware, and the encrypted
Grager backdoor into a file named `data.dat` ref [1].   

The backdoor leverages a custom application layer protocol for
communication with its command and control server, allowing it to bypass
traditional network security tools and evade detection. Grager employs
various stealth techniques, such as obfuscation and anti-analysis methods,
to evade antivirus software and remain undetected.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor uses vulnerable Microsoft Graph APIs to deploy
the malware and contact the C&C server.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: Workstations, Customer, Desktop, Control Server, Media
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Business disruption; Impairement; Data Breach; Reputational Damages | - |
| Leverage | Dwelling; Infrastructure Compromise; Elevation of privilege; Information Disclosure; Software installation | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Exploitation | Techniques to exploit vulnerabilities in systems that may, amongst others, result in code execution. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1071` | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071) | Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.   Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.(Citation: Mandiant APT29 Eye Spy Email Nov 22) |
| `T1105` | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)).   On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, [certutil](https://attack.mitre.org/software/S0160), and [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.(Citation: t1105_lolbas)  A number of these tools, such as `wget`, `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor may attempt to verify its integrity by checking its hash value (e.g., via `certutil -hashfile`).(Citation: Google Cloud Threat Intelligence COSCMICENERGY 2023)  Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts. Adversaries have also abused file application features, such as the Windows `search-ms` protocol handler, to deliver malicious files to victims through remote file searches invoked by [User Execution](https://attack.mitre.org/techniques/T1204) (typically after interacting with [Phishing](https://attack.mitre.org/techniques/T1566) lures).(Citation: T1105: Trellix_search-ms)  Files can also be transferred using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well as native or otherwise present tools on the victim system.(Citation: PTSecurity Cobalt Dec 2016) In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.(Citation: Dropbox Malware Sync) |
| `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).  There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).  Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python) |
