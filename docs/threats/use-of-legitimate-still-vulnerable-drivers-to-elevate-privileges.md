# Use of legitimate still vulnerable drivers to elevate privileges

## Metadata

- **UUID**: `a5761988-391d-4cd3-8ade-690bd3315943`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-08-18`
- **Modified**: `2025-08-22`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.securityweek.com/dozens-of-kernel-drivers-allow-attackers-to-alter-firmware-escalate-privileges](https://www.securityweek.com/dozens-of-kernel-drivers-allow-attackers-to-alter-firmware-escalate-privileges)
- **2**: [https://www.polimetro.com/en/What-is-Microsoft-Vulnerable-Driver-Blocklist](https://www.polimetro.com/en/What-is-Microsoft-Vulnerable-Driver-Blocklist)
- **3**: [https://www.eset.com/us/about/newsroom/corporate-blog/taking-down-turla-balancing-act-between-visibility-usability-with-eset](https://www.eset.com/us/about/newsroom/corporate-blog/taking-down-turla-balancing-act-between-visibility-usability-with-eset)
- **4**: [https://securityaffairs.com/133546/intelligence/candiru-chrome-zero-day.html](https://securityaffairs.com/133546/intelligence/candiru-chrome-zero-day.html)
- **5**: [https://www.csoonline.com/article/4034988/akira-affiliates-abuse-legitimate-windows-drivers-to-evade-detection-in-sonicwall-attacks.html](https://www.csoonline.com/article/4034988/akira-affiliates-abuse-legitimate-windows-drivers-to-evade-detection-in-sonicwall-attacks.html)
- **6**: [https://www.loldrivers.io/](https://www.loldrivers.io/)
- **7**: [https://github.com/splunk/security_content/blob/develop/lookups/loldrivers.csv](https://github.com/splunk/security_content/blob/develop/lookups/loldrivers.csv)

## Description
Threat actors can use legitimate and code-signed, but vulnerable drivers to 
execute kernel-level code in order to elevate privileges or disable security 
products. Such drivers can allow malicious actors to manipulate system 
components, processes, maintain persistence on a system and evade security 
products ref [1].

Microsoft and other vendors have created and maintain vulnerable driver 
lists ref [2], [6], [7], for example to thwart and isolate drivers which are 
vulnerable or with a high risk for explaoitation. The drivers with a 
previously discovered vulnerabilites can also be considered for review and
as good candidates for a block list or monitoring.  

The vulnerable signed drivers can come from a variety of vendors such as,
but not limited to, ASROCK, ASUSTeK, IBM.  

### List of some vulnerable signed drivers, which have been exploited in 
the past

- `win32k.sys` - it's a kernel-mode driver that has been exploited in
   various ways, including elevation of privilege (EoP) vulnerabilities.
- `splwow64.sys` - this is a vulnerable driver which lets local code
  escalation by abusing the print stack broker.
- `dxgkrnl.sys` - this driver is responsible for graphics rendering and has
  been vulnerable to exploits. It's related to a validation flaw enabling
  local EoP in the DirectX graphics kernel driver.
- `tdx.sys`: The TDx driver has been exploited in the past, including a
  vulnerability that allows remote code execution (RCE). Other vulnerability
  buffer over-read allows local EoP on multiple Windows versions; patched
  July 2025.
- `splwow64.sys` - this driver is responsible for print spooling and has
   been vulnerable to exploits.
- `cng.sys` - the Cryptography Next Generation (CNG) driver has been
  exploited, including a vulnerability (CVE-2020-1145) that allowed EoP.
- `msrpc.sys` - it's Microsoft Remote Procedure Call (MSRPC) driver has been
  vulnerable to exploits. 
- `ucx01000.sys` - this driver is part of the USB driver stack and has been
  exploited. 
- `ndis.sys` - the Network Driver Interface Specification (NDIS) driver has
  been vulnerable to exploits. Example for an exploit: EoP precedent where
  buffer length checks were insufficient.  
- `wdf01000.sys` - this is Windows Driver Framework (WDF) driver which can
   be exploited by the threat actors for privilege escalation and other
   purposes.
- `storport.sys` - the Storage Port driver can be vulnerable to exploits.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor uses software vulnerabilities in legitimate Windows or other 
driver. The adversary already has local code execution (e.g., user context),
can trigger the vulnerable IOCTL/syscall surface, and the system is not yet
patched.

Domains: Enterprise
Targets: Laptop, Workstations, Customer, End-user, Virtual Machines
Platforms: Windows, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Impairement | - |
| Leverage | Elevation of privilege; Infrastructure Compromise; Tampering; Modify configuration; Software installation | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| Turla | `misp::fa80877c-f509-4daf-8b62-20aba1635f68` | ('misp',) | A 2014 Guardian article described Turla as: 'Dubbed the Turla hackers, initial intelligence had indicated western powers were key targets, but it was later determined embassies for Eastern Bloc nations were of more interest. Embassies in Belgium, Ukraine, China, Jordan, Greece, Kazakhstan, Armenia, Poland, and Germany were all attacked, though researchers from Kaspersky Lab and Symantec could not confirm which countries were the true targets. In one case from May 2012, the office of the prime minister of a former Soviet Union member country was infected, leading to 60 further computers being affected, Symantec researchers said. There were some other victims, including the ministry for health of a Western European country, the ministry for education of a Central American country, a state electricity provider in the Middle East and a medical organisation in the US, according to Symantec. It is believed the group was also responsible for a much - documented 2008 attack on the US Central Command. The attackers - who continue to operate - have ostensibly sought to carry out surveillance on targets and pilfer data, though their use of encryption across their networks has made it difficult to ascertain exactly what the hackers took.Kaspersky Lab, however, picked up a number of the attackers searches through their victims emails, which included terms such as Nato and EU energy dialogue Though attribution is difficult to substantiate, Russia has previously been suspected of carrying out the attacks and Symantecs Gavin O’ Gorman told the Guardian a number of the hackers appeared to be using Russian names and language in their notes for their malicious code. Cyrillic was also seen in use.' |
| [[Enterprise] Turla](https://attack.mitre.org/groups/G0010) | `att&ck::G0010` | ('att&ck',) | [Turla](https://attack.mitre.org/groups/G0010) is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB).  They have compromised victims in over 50 countries since at least 2004, spanning a range of industries including government, embassies, military, education, research and pharmaceutical companies. [Turla](https://attack.mitre.org/groups/G0010) is known for conducting watering hole and spearphishing campaigns, and leveraging in-house tools and malware, such as [Uroburos](https://attack.mitre.org/software/S0022).(Citation: Kaspersky Turla)(Citation: ESET Gazer Aug 2017)(Citation: CrowdStrike VENOMOUS BEAR)(Citation: ESET Turla Mosquito Jan 2018)(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023) |
| Caramel Tsunami | `misp::062938a2-6fa1-4217-ad73-f5e0b5186966` | ('misp',) | Caramel Tsunami is a threat actor that specializes in spyware attacks. They have recently resurfaced with an updated toolset and zero-day exploits, targeting specific victims through watering hole attacks. Candiru has been observed exploiting vulnerabilities in popular browsers like Google Chrome and using third-party signed drivers to gain access to the Windows kernel. They have also been linked to other spyware vendors and have been associated with extensive abuses of their surveillance tools. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1547.006` | [Boot or Logon Autostart Execution: Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006) | Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system.(Citation: Linux Kernel Programming)xa0  When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0).(Citation: Linux Kernel Module Programming Guide)xa0Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users.(Citation: iDefense Rootkit Overview)  Kernel extensions, also called kext, are used in macOS to load functionality onto a system similar to LKMs for Linux. Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies. Kexts are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands. Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions. Developers without these privileges may still sign kexts but they will not load unless SIP is disabled. If SIP is enabled, the kext signature is verified before being added to the AuxKC.(Citation: System and kernel extensions in macOS)  Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces.(Citation: Apple Kernel Extension Deprecation)  Adversaries can use LKMs and kexts to conduct [Persistence](https://attack.mitre.org/tactics/TA0003) and/or [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) on a system. Examples have been found in the wild, and there are some relevant open source projects as well.(Citation: Volatility Phalanx2)(Citation: CrowdStrike Linux Rootkit)(Citation: GitHub Reptile)(Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco Patrick Wardle)(Citation: Synack Secure Kernel Extension Broken)(Citation: Securelist Ventir)(Citation: Trend Micro Skidmap) |
| `T1068` | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) | Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.  When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods.  Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020) Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) or [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570). |
| `T1547` | [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547) | Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.  Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges. |
