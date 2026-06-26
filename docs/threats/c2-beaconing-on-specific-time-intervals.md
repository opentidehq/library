# C2 beaconing on specific time intervals

## Metadata

- **UUID**: `7b122bb4-fc13-438b-a052-4388c501ec59`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-08-22`
- **Modified**: `2025-08-26`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://hunt.io/glossary/c2-beaconing](https://hunt.io/glossary/c2-beaconing)
- **2**: [https://systemweakness.com/detecting-malware-c2-traffic-a-step-by-step-guide-using-splunk-python-19a1b9500772](https://systemweakness.com/detecting-malware-c2-traffic-a-step-by-step-guide-using-splunk-python-19a1b9500772)
- **3**: [https://thecyberthrone.in/2025/07/05/nighteagle-apt-targeted-zero-day-exploitation-campaign](https://thecyberthrone.in/2025/07/05/nighteagle-apt-targeted-zero-day-exploitation-campaign)
- **4**: [https://securityonline.info/nighteagle-apt-group-soars-over-chinas-critical-tech-zero-days-exchange-exploits-and-tailored-espionage](https://securityonline.info/nighteagle-apt-group-soars-over-chinas-critical-tech-zero-days-exchange-exploits-and-tailored-espionage)
- **5**: [https://www.geeksforgeeks.org/ethical-hacking/beaconing-in-cyber-security](https://www.geeksforgeeks.org/ethical-hacking/beaconing-in-cyber-security)

## Description
C2 beaconing refers to the periodic communication between a compromised
system and a Command and Control (C2) server. The packets are sent from the
infected host to the C2 server at regular intervals, known as the `beacon
interval`, which can be down to the second to avoid suspicion. For example,
a Cobalt Strike beacon might have an average sleep of several seconds with
jitter added to disrupt the pattern. The compromised system, often is
referred as a "beacon" sends periodic signals or "beacons" to the C2 for
one of the following reasons ref [1].

- Check for new commands or updates
- Report back on its status or activities
- Receive instructions or configuration changes
- C2 beaconing on specific time intervals

To avoid detection, attackers often configure the compromised system to
beacon on specific time intervals.

### Possible C2 beaconing set-up

A threat actor can set C2 server to respond in one of the following ways.

- Fixed intervals: The beacon sends signals at fixed intervals, e.g., every
  5 minutes, 1 hour, or 24 hours.
- Randomised intervals: The beacon sends signals at randomised intervals,
  e.g., between 5-15 minutes, to make it harder to detect.
- Scheduled intervals: The beacon sends signals at specific times, e.g.,
  during business hours or when the system is most active.

### Threat actor's purposes

Attackers can set a specific timing or rules in their Command and Control
servers depends on different reasons and goals.

- Evade detection: By beaconing at regular intervals, the attacker can avoid
  detection by security systems that rely on anomaly detection or behavioral
  analysis.
- Maintain stealth: By using fixed or randomized intervals, the attacker can
  make it harder for security teams to detect the beaconing activity.
- Conserve resources: By only communicating at specific intervals, the
  attacker can conserve resources, such as bandwidth and system resources,
  on the compromised system.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor uses a compromised endpoint to set and monitor specific time
intervals known as beacons.

Domains: Enterprise
Targets: Customer, Workstations, End-user
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Data Breach | Non-public information has been accessed from the outside, and successfully extracted. |
| Leverage | Dwelling; Information Disclosure | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Exfiltration | Techniques that result or aid in an attacker removing data from a target network. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1205` | [Traffic Signaling](https://attack.mitre.org/techniques/T1205) | Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. [Port Knocking](https://attack.mitre.org/techniques/T1205/001)), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.  Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).  The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.  On network devices, adversaries may use crafted packets to enable [Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.  Adversaries may use crafted packets to attempt to connect to one or more (open or closed) ports, but may also attempt to connect to a router interface, broadcast, and network address IP on the same port in order to achieve their goals and objectives.(Citation: Cisco Synful Knock Evolution)(Citation: Mandiant - Synful Knock)(Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage [Patch System Image](https://attack.mitre.org/techniques/T1601/001) due to the monolithic nature of the architecture.  Adversaries may also use the Wake-on-LAN feature to turn on powered off systems. Wake-on-LAN is a hardware feature that allows a powered down system to be powered on, or woken up, by sending a magic packet to it. Once the system is powered on, it may become a target for lateral movement.(Citation: Bleeping Computer - Ryuk WoL)(Citation: AMD Magic Packet) |
| `T1029` | [Scheduled Transfer](https://attack.mitre.org/techniques/T1029) | Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.  When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) or [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048). |
