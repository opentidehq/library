# Abuse of special permission via chmod on files

## Metadata

- **UUID**: `52cd3405-ddd8-40cd-be83-640a21c2b4c4`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-01-13`
- **Modified**: `2025-01-16`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://research.splunk.com/endpoint/8230c407-1b47-4d95-ac2e-718bd6381386/](https://research.splunk.com/endpoint/8230c407-1b47-4d95-ac2e-718bd6381386/)
- **2**: [https://www.thehacker.recipes/infra/privilege-escalation/unix/suid-sgid-binaries](https://www.thehacker.recipes/infra/privilege-escalation/unix/suid-sgid-binaries)

## Description
Attackers leverage the `chmod` utility to set the SUID (Set Owner User ID), 
the SGID (Set Owner Group ID), or the Sticky bit on executables or scripts. 
By abusing these bits, an adversary can temporarily inherit root- 
or group-level privileges when the affected file is executed.  

This effectively grants them elevated rights that can be used to move laterally 
within the environment, access or exfiltrate sensitive data, or escalate 
privileges to maintain a stronger foothold on the system.  

Examples of SUID, SGID, and Sticky bit abuse:

SUID shell: Attackers can create a file with the setuid bit set and owned
by the root user, and then use that file to gain root privileges and 
execute a shell with root privileges.

SGID exploit: Attackers can find a file with the setgid bit set and owned
by a group that has elevated privileges, and then use that file to gain the
privileges of that group.

Sticky bit exploit: Attackers can set the sticky bit on a file to prevent
it from being deleted or renamed, and then use that file to store malicious
code or data.

In many Linux-based distributions (and similarly on macOS systems), 
`chmod` is widely available and not restricted in typical configurations. 
Attackers can take advantage of this by running commands such as:

```bash
chmod u+s /path/to/executable
```

or

```bash
chmod g+s /path/to/executable
```
Depending on permissions misconfigurations, these commands may succeed if the 
account in use has the necessary rights or if the system’s sudo settings 
are overly permissive.  

Once the SUID or SGID bit is set on a critical binary, any user running that 
binary subsequently executes it with elevated privileges. Threat actors have 
been observed employing this technique to gain root-level access, tamper with 
system logs, exfiltrate proprietary data, or introduce backdoors for persistence.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **An adversary must have local or SSH access to the target system, with credentials 
allowing the use of chmod or sudo. Typically, this involves default or weak 
configurations enabling chmod modifications on critical executables or scripts.

Domains: Enterprise
Targets: Workstations, Public-Facing Servers, Laptop
Platforms: Linux, macOS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Reputational Damages; Data Breach; Operating costs | - |
| Leverage | Elevation of privilege; Modify privileges; Dwelling; Log tampering; Information Disclosure | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] TeamTNT](https://attack.mitre.org/groups/G0139) | `att&ck::G0139` | ('att&ck',) | [TeamTNT](https://attack.mitre.org/groups/G0139) is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.(Citation: Palo Alto Black-T October 2020)(Citation: Lacework TeamTNT May 2021)(Citation: Intezer TeamTNT September 2020)(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro TeamTNT)(Citation: ATT TeamTNT Chimaera September 2020)(Citation: Aqua TeamTNT August 2020)(Citation: Intezer TeamTNT Explosion September 2021) |
| TeamTNT | `misp::27de6a09-844b-4dcb-9ff9-7292aad826ba` | ('misp',) | In early Febuary, 2021 TeamTNT launched a new campaign against Docker and Kubernetes environments. Using a collection of container images that are hosted in Docker Hub, the attackers are targeting misconfigured docker daemons, Kubeflow dashboards, and Weave Scope, exploiting these environments in order to steal cloud credentials, open backdoors, mine cryptocurrency, and launch a worm that is looking for the next victim. They're linked to the First Crypto-Mining Worm to Steal AWS Credentials and Hildegard Cryptojacking malware. TeamTNT is a relatively recent addition to a growing number of threats targeting the cloud. While they employ some of the same tactics as similar groups, TeamTNT stands out with their social media presence and penchant for self-promotion. Tweets from the TeamTNT’s account are in both English and German although it is unknown if they are located in Germany. |
| [[Enterprise] APT38](https://attack.mitre.org/groups/G0082) | `att&ck::G0082` | ('att&ck',) | [APT38](https://attack.mitre.org/groups/G0082) is a North Korean state-sponsored threat group that specializes in financial cyber operations; it has been attributed to the Reconnaissance General Bureau.(Citation: CISA AA20-239A BeagleBoyz August 2020) Active since at least 2014, [APT38](https://attack.mitre.org/groups/G0082) has targeted banks, financial institutions, casinos, cryptocurrency exchanges, SWIFT system endpoints, and ATMs in at least 38 countries worldwide. Significant operations include the 2016 Bank of Bangladesh heist, during which [APT38](https://attack.mitre.org/groups/G0082) stole $81 million, as well as attacks against Bancomext (Citation: FireEye APT38 Oct 2018) and Banco de Chile (Citation: FireEye APT38 Oct 2018); some of their attacks have been destructive.(Citation: CISA AA20-239A BeagleBoyz August 2020)(Citation: FireEye APT38 Oct 2018)(Citation: DOJ North Korea Indictment Feb 2021)(Citation: Kaspersky Lazarus Under The Hood Blog 2017)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups. |
| Lazarus Group | `misp::68391641-859f-4a9a-9a1e-3e5cf71ec376` | ('misp',) | Since 2009, HIDDEN COBRA actors have leveraged their capabilities to target and compromise a range of victims; some intrusions have resulted in the exfiltration of data while others have been disruptive in nature. Commercial reporting has referred to this activity as Lazarus Group and Guardians of Peace. Tools and capabilities used by HIDDEN COBRA actors include DDoS botnets, keyloggers, remote access tools (RATs), and wiper malware. Variants of malware and tools used by HIDDEN COBRA actors include Destover, Duuzer, and Hangman. |
| [[Enterprise] Wizard Spider](https://attack.mitre.org/groups/G0102) | `att&ck::G0102` | ('att&ck',) | [Wizard Spider](https://attack.mitre.org/groups/G0102) is a Russia-based financially motivated threat group originally known for the creation and deployment of [TrickBot](https://attack.mitre.org/software/S0266) since at least 2016. [Wizard Spider](https://attack.mitre.org/groups/G0102) possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.(Citation: CrowdStrike Ryuk January 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: CrowdStrike Wizard Spider October 2020) |
| UNC1878 | `misp::3c2bb7d7-a085-4594-adc7-4a20cf724abb` | ('misp',) | UNC1878 is a financially motivated threat actor that monetizes network access via the deployment of RYUK ransomware. Earlier this year, Mandiant published a blog on a fast-moving adversary deploying RYUK ransomware, UNC1878. Shortly after its release, there was a significant decrease in observed UNC1878 intrusions and RYUK activity overall almost completely vanishing over the summer. But beginning in early fall, Mandiant has seen a resurgence of RYUK along with TTP overlaps indicating that UNC1878 has returned from the grave and resumed their operations. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1548.001` | [Abuse Elevation Control Mechanism: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001) | An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively.(Citation: setuid man page) Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges.  Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications (i.e. [Linux and Mac File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/002)). The <code>chmod</code> command can set these bits with bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, <code>chmod u+s [file]</code>. This will enable the setuid bit. To enable the setgid bit, <code>chmod 2775</code> and <code>chmod g+s</code> can be used.  Adversaries can use this mechanism on their own malware to make sure they're able to execute in elevated contexts in the future.(Citation: OSX Keydnap malware) This abuse is often part of a "shell escape" or other actions to bypass an execution environment with restricted permissions.  Alternatively, adversaries may choose to find and target vulnerable binaries with the setuid or setgid bits already enabled (i.e. [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)). The setuid and setguid bits are indicated with an "s" instead of an "x" when viewing a file's attributes via <code>ls -l</code>. The <code>find</code> command can also be used to search for such files. For example, <code>find / -perm +4000 2>/dev/null</code> can be used to find files with setuid set and <code>find / -perm +2000 2>/dev/null</code> may be used for setgid. Binaries that have these bits set may then be abused by adversaries.(Citation: GTFOBins Suid) |
