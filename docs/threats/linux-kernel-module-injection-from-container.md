# Linux kernel module injection from container

## Metadata

- **UUID**: `dcccd7e5-9d3f-4b36-853a-5cd18a7ef752`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2023-01-09`
- **Modified**: `2023-01-10`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.giac.org/paper/gsec/935/kernel-rootkits/101864](https://www.giac.org/paper/gsec/935/kernel-rootkits/101864)
- **2**: [https://www.zdnet.com/article/this-new-linux-malware-has-a-sneaky-way-of-staying-hidden/](https://www.zdnet.com/article/this-new-linux-malware-has-a-sneaky-way-of-staying-hidden/)
- **3**: [https://github.com/milabs/awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits)
- **4**: [https://www.debian.org/doc/manuals/securing-debian-manual/ch10s04.en.html](https://www.debian.org/doc/manuals/securing-debian-manual/ch10s04.en.html)

## Description
Loadable Kernel Modules (LKM) can be used by adversaries to deliver 
sophisticated and hard to detect rootkits. Each event where kernel modules 
are loaded from a container should be investigated with the exeption of 
Security tools deployed in containers.

An injected kernel module is just code execution, and can in theory do 
more or less anything, but threat actors mostly use this for dwelling and 
for hiding their presence on a system.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actor has already escalated privileges to root via an exploit on a 
unprivileged container host, or the threat actor exploited an application 
running in a highly privileged container, which means a host running 
highly privileged containers with CAP_NET_ADMIN or CAP_SYS_MODULE 
capabilities or Kubernetes pods running in privileged mode.

Domains: Embedded, Enterprise, Private Cloud, Public Cloud
Targets: Compute Cluster, Microservices, Virtual Machines Host
Platforms: Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Impairement; Lose Capabilities | - |
| Leverage | Dwelling; Infrastructure Compromise; Repudiation; Software installation | - |
| Viability | Environment dependent | Depends |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1547.006` | [Boot or Logon Autostart Execution: Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006) | Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system.(Citation: Linux Kernel Programming)xa0  When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0).(Citation: Linux Kernel Module Programming Guide)xa0Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users.(Citation: iDefense Rootkit Overview)  Kernel extensions, also called kext, are used in macOS to load functionality onto a system similar to LKMs for Linux. Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies. Kexts are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands. Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions. Developers without these privileges may still sign kexts but they will not load unless SIP is disabled. If SIP is enabled, the kext signature is verified before being added to the AuxKC.(Citation: System and kernel extensions in macOS)  Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces.(Citation: Apple Kernel Extension Deprecation)  Adversaries can use LKMs and kexts to conduct [Persistence](https://attack.mitre.org/tactics/TA0003) and/or [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) on a system. Examples have been found in the wild, and there are some relevant open source projects as well.(Citation: Volatility Phalanx2)(Citation: CrowdStrike Linux Rootkit)(Citation: GitHub Reptile)(Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco Patrick Wardle)(Citation: Synack Secure Kernel Extension Broken)(Citation: Securelist Ventir)(Citation: Trend Micro Skidmap) |
