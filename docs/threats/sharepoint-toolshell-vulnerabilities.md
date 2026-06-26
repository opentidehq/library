# SharePoint ToolShell vulnerabilities

## Metadata

- **UUID**: `55227203-38dc-406b-943a-9c1c6023d1cd`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-07-28`
- **Modified**: `2025-08-16`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.trendmicro.com/en_us/research/25/g/cve-2025-53770-and-cve-2025-53771-sharepoint-attacks.html](https://www.trendmicro.com/en_us/research/25/g/cve-2025-53770-and-cve-2025-53771-sharepoint-attacks.html)
- **2**: [https://research.eye.security/sharepoint-under-siege](https://research.eye.security/sharepoint-under-siege)
- **3**: [https://msrc.microsoft.com/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770](https://msrc.microsoft.com/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770)
- **4**: [https://thehackernews.com/2025/07/microsoft-releases-urgent-patch-for.html](https://thehackernews.com/2025/07/microsoft-releases-urgent-patch-for.html)
- **5**: [https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-sharepoint-enterprise-server-2016-july-8-2025-kb5002744-9196e240-c76d-4bb0-b16c-6f7d6645a1f0](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-sharepoint-enterprise-server-2016-july-8-2025-kb5002744-9196e240-c76d-4bb0-b16c-6f7d6645a1f0)
- **6**: [https://securityaffairs.com/180267/apt/microsoft-linked-attacks-on-sharepoint-flaws-to-china-nexus-actors.html](https://securityaffairs.com/180267/apt/microsoft-linked-attacks-on-sharepoint-flaws-to-china-nexus-actors.html)
- **7**: [https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities)
- **8**: [https://thehackernews.com/2025/07/storm-2603-exploits-sharepoint-flaws-to.html](https://thehackernews.com/2025/07/storm-2603-exploits-sharepoint-flaws-to.html)
- **9**: [https://thehackernews.com/2025/07/microsoft-links-ongoing-sharepoint.html](https://thehackernews.com/2025/07/microsoft-links-ongoing-sharepoint.html)
- **10**: [https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities)

## Description
SharePoint zero-day vulnerabilities, known also as `ToolShell` are affecting
on-premise Microsoft SharePoint servers, which enable the attackers to
execute code on SharePoint servers without authentication, bypassing
security mechanisms. This vulnerabilities are considered with a high
security risk because they may lead to a remote code execution (RCE)
and a fully compromise of a SharePoint environment. 

What is known until now for these vulnerabilities is that a threat actor
deploys initially a malicious ASPX file `spinstall0.aspx`, also knows as
`SharpyShell`. The malicious file purpose is to extract and leak
cryptographic secrets from the SharePoint server using a simple GET request.
The goal of the threat actor is to obtain the server's MachineKey
configuration, including the critical ValidationKey , which are essential
for generating valid payloads ref [1].    

With these keys, the attackers can effectively turn any authenticated
SharePoint request into a remote code execution opportunity, bypassing the
need for credentials and gaining full control of the server.  

The attacker then uses a tool called `ysoserial` to craft their own valid
SharePoint token for remote code execution with full persistence and no
authentication ref [2].

It was identified successful zero-day exploitation in the SharePoint systems
of at least seven Union entities. But those incidents were not considered
as severe incident because the Defender EDR blocked post-compromise attempts.
Based on the current analysis and investigation there was not detected any
leak of credentials used for post-exploitation activities.

At this moment Microsoft released new SharePoint patches to fix these
vulnerabilities. Microsoft has released security updates that fully protect
customers using all supported versions of SharePoint affected by these two
vulnerabilities. For more information about patching review the customer
guidance for SharePoint vulnerability ref [3],[4].

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Vulnerable SharePoint server allowing unauthenticated requests leading to
remote code execution.

Domains: Enterprise
Cve: CVE-2025-53770, CVE-2025-53771
Targets: Public-Facing Servers, Customer, End-user, Remote access, System admin
Platforms: Microsoft SharePoint, Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Highly significant incident | A cyber attack which has a serious impact on central government, (inter)national essential services, a large proportion of the (inter)national population, or the (inter)national economy. |
| Impact | Data Breach; Identity Theft; Reputational Damages | - |
| Leverage | Infrastructure Compromise; Information Disclosure; Spoofing; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Threat Group-3390](https://attack.mitre.org/groups/G0027) | `att&ck::G0027` | ('att&ck',) | [Threat Group-3390](https://attack.mitre.org/groups/G0027) is a Chinese threat group that has extensively used strategic Web compromises to target victims.(Citation: Dell TG-3390) The group has been active since at least 2010 and has targeted organizations in the aerospace, government, defense, technology, energy, manufacturing and gambling/betting sectors.(Citation: SecureWorks BRONZE UNION June 2017)(Citation: Securelist LuckyMouse June 2018)(Citation: Trend Micro DRBControl February 2020) |
| APT27 | `misp::834e0acd-d92a-4e38-bb14-dc4159d7cb32` | ('misp',) | A China-based actor that targets foreign embassies to collect data on government, defence, and technology sectors. |
| [[Enterprise] ZIRCONIUM](https://attack.mitre.org/groups/G0128) | `att&ck::G0128` | ('att&ck',) | [ZIRCONIUM](https://attack.mitre.org/groups/G0128) is a threat group operating out of China, active since at least 2017, that has targeted individuals associated with the 2020 US presidential election and prominent leaders in the international affairs community.(Citation: Microsoft Targeting Elections September 2020)(Citation: Check Point APT31 February 2021) |
| APT31 | `misp::6bf7e6b6-5917-45a6-9567-f0baba79768c` | ('misp',) | FireEye characterizes APT31 as an actor specialized on intellectual property theft, focusing on data and projects that make a particular organization competetive in its field. Based on available data (April 2016), FireEye assesses that APT31 conducts network operations at the behest of the Chinese Government. Also according to Crowdstrike, this adversary is suspected of continuing to target upstream providers (e.g., law firms and managed service providers) to support additional intrusions against high-profile assets. In 2018, CrowdStrike observed this adversary using spear-phishing, URL “web bugs” and scheduled tasks to automate credential harvesting. |
| [[Enterprise] MoustachedBouncer](https://attack.mitre.org/groups/G1019) | `att&ck::G1019` | ('att&ck',) | [MoustachedBouncer](https://attack.mitre.org/groups/G1019) is a cyberespionage group that has been active since at least 2014 targeting foreign embassies in Belarus.(Citation: MoustachedBouncer ESET August 2023) |
| Storm-2603 | `misp::981402be-3b2d-4310-a7c6-c773aec869c1` | ('misp',) | The group Microsoft tracks as Storm-2603 is assessed with medium confidence to be a China-based threat actor. Microsoft has not identified links between Storm-2603 and other known Chinese threat actors. Microsoft tracks this threat actor in association with attempts to steal MachineKeys via the on-premises SharePoint vulnerabilities. Although Microsoft has observed this threat actor deploying Warlock and Lockbit ransomware in the past, Microsoft is currently unable to confidently assess the threat actor’s objectives.  Additional actors may use these exploits to target unpatched on-premises SharePoint systems, further emphasizing the need for organizations to implement mitigations and security updates immediately. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
| `T1212` | [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212) | Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.xa0  Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain authenticated access to systems. One example of this is `MS14-068`, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.(Citation: Technet MS14-068)(Citation: ADSecurity Detecting Forged Tickets) Another example of this is replay attacks, in which the adversary intercepts data packets sent between parties and then later replays these packets. If services don't properly validate authentication requests, these replayed packets may allow an adversary to impersonate one of the parties and gain unauthorized access or privileges.(Citation: Bugcrowd Replay Attack)(Citation: Comparitech Replay Attack)(Citation: Microsoft Midnight Blizzard Replay Attack)  Such exploitation has been demonstrated in cloud environments as well. For example, adversaries have exploited vulnerabilities in public cloud infrastructure that allowed for unintended authentication token creation and renewal.(Citation: Storm-0558 techniques for unauthorized email access)  Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained. |
| `T1078` | [Valid Accounts](https://attack.mitre.org/techniques/T1078) | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.(Citation: volexity_0day_sophos_FW) Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.  In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.(Citation: CISA MFA PrintNightmare)  The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.(Citation: TechNet Credential Theft) |
