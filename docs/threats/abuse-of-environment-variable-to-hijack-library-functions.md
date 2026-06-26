# Abuse of environment variable to hijack library functions

## Metadata

- **UUID**: `4d0bd987-1430-4433-9b58-a71ba8798435`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-01-10`
- **Modified**: `2025-01-10`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://research.splunk.com/endpoint/35c50572-a70b-452f-afa9-bebdf3c3ce36/](https://research.splunk.com/endpoint/35c50572-a70b-452f-afa9-bebdf3c3ce36/)
- **2**: [https://www.getambassador.io/blog/code-injection-on-linux-and-macos](https://www.getambassador.io/blog/code-injection-on-linux-and-macos)
- **3**: [https://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/](https://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/)

## Description
This threat vector focuses on the malicious use of the `LD_PRELOAD` environment 
variable on Linux systems to hook or hijack library function calls. Attackers, 
Red Teams, and advanced persistent threats leverage this trick to intercept and 
modify the behavior of dynamically linked libraries before the legitimate 
functions are called. By loading a rogue or malicious library via `LD_PRELOAD`, 
adversaries can achieve elevated privileges, persist on the target, and run 
arbitrary code under the guise of otherwise legitimate processes.    

Scenario example: 
- An attacker already possessing local or remote administrative access to a Linux 
host can set or modify the `LD_PRELOAD` environment variable in order to inject 
custom libraries during program execution.   

- When an application starts, the system dynamic linker reads the `LD_PRELOAD` variable 
and forces the loading of the malicious library.  

- The malicious library intercepts and potentially manipulates function calls—such as 
file I/O or network operations—allowing attackers to subvert security controls or 
execute code of their choice.

```bash
LD_PRELOAD=/tmp/malicious.so /usr/bin/anyApp
```

This indicates that a potentially unauthorized library (`/tmp/malicious.so`) is being 
force-loaded into `anyApp`.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actor must have sufficient privileges to modify environment variables or 
system configurations and deploy malicious libraries in the filesystem in order 
to hijack library calls via LD_PRELOAD.

Domains: Enterprise
Targets: Workstations, Public-Facing Servers, Server Logs
Platforms: Linux, Docker Engine, Kubernetes**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Business disruption; Monetary Loss; Reputational Damages | - |
| Leverage | Elevation of privilege; Modify configuration; Software installation; Infrastructure Compromise; Alter behavior | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] TeamTNT](https://attack.mitre.org/groups/G0139) | `att&ck::G0139` | ('att&ck',) | [TeamTNT](https://attack.mitre.org/groups/G0139) is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.(Citation: Palo Alto Black-T October 2020)(Citation: Lacework TeamTNT May 2021)(Citation: Intezer TeamTNT September 2020)(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro TeamTNT)(Citation: ATT TeamTNT Chimaera September 2020)(Citation: Aqua TeamTNT August 2020)(Citation: Intezer TeamTNT Explosion September 2021) |
| TeamTNT | `misp::27de6a09-844b-4dcb-9ff9-7292aad826ba` | ('misp',) | In early Febuary, 2021 TeamTNT launched a new campaign against Docker and Kubernetes environments. Using a collection of container images that are hosted in Docker Hub, the attackers are targeting misconfigured docker daemons, Kubeflow dashboards, and Weave Scope, exploiting these environments in order to steal cloud credentials, open backdoors, mine cryptocurrency, and launch a worm that is looking for the next victim. They're linked to the First Crypto-Mining Worm to Steal AWS Credentials and Hildegard Cryptojacking malware. TeamTNT is a relatively recent addition to a growing number of threats targeting the cloud. While they employ some of the same tactics as similar groups, TeamTNT stands out with their social media presence and penchant for self-promotion. Tweets from the TeamTNT’s account are in both English and German although it is unknown if they are located in Germany. |
| [[Enterprise] APT37](https://attack.mitre.org/groups/G0067) | `att&ck::G0067` | ('att&ck',) | [APT37](https://attack.mitre.org/groups/G0067) is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, India, Romania, Kuwait, and other parts of the Middle East. [APT37](https://attack.mitre.org/groups/G0067) has also been linked to the following campaigns between 2016-2018: Operation Daybreak, Operation Erebus, Golden Time, Evil New Year, Are you Happy?, FreeMilk, North Korean Human Rights, and Evil New Year 2018.(Citation: FireEye APT37 Feb 2018)(Citation: Securelist ScarCruft Jun 2016)(Citation: Talos Group123)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups. |
| APT37 | `misp::50cd027f-df14-40b2-aa22-bf5de5061163` | ('misp',) | APT37 has likely been active since at least 2012 and focuses on targeting the public and private sectors primarily in South Korea. In 2017, APT37 expanded its targeting beyond the Korean peninsula to include Japan, Vietnam and the Middle East, and to a wider range of industry verticals, including chemicals, electronics, manufacturing, aerospace, automotive and healthcare entities |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1574.006` | [Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) | Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from various environment variables and files, such as <code>LD_PRELOAD</code> on Linux or <code>DYLD_INSERT_LIBRARIES</code> on macOS.(Citation: TheEvilBit DYLD_INSERT_LIBRARIES)(Citation: Timac DYLD_INSERT_LIBRARIES)(Citation: Gabilondo DYLD_INSERT_LIBRARIES Catalina Bypass) Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries)(Citation: Apple Doco Archive Dynamic Libraries) Each platform's linker uses an extensive list of environment variables at different points in execution. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions in the original library.(Citation: Baeldung LD_PRELOAD)  Hijacking dynamic linker variables may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. On Linux, adversaries may set <code>LD_PRELOAD</code> to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program. For example, adversaries have used `LD_PRELOAD` to inject a malicious library into every descendant process of the `sshd` daemon, resulting in execution under a legitimate process. When the executing sub-process calls the `execve` function, for example, the malicious library’s `execve` function is executed rather than the system function `execve` contained in the system library on disk. This allows adversaries to [Hide Artifacts](https://attack.mitre.org/techniques/T1564) from detection, as hooking system functions such as `execve` and `readdir` enables malware to scrub its own artifacts from the results of commands such as `ls`, `ldd`, `iptables`, and `dmesg`.(Citation: ESET Ebury Oct 2017)(Citation: Intezer Symbiote 2022)(Citation: Elastic Security Labs Pumakit 2024)  Hijacking dynamic linker variables may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. |
