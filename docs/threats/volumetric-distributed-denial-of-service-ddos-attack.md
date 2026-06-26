# Volumetric Distributed denial of service (DDoS) attack

## Metadata

- **UUID**: `78e05130-58a9-49cd-9039-3d7f9ac0bcb5`
- **Schema**: `threat::1.0`
- **Version**: `4`
- **Created**: `2022-11-23`
- **Modified**: `2023-01-23`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://en.wikipedia.org/wiki/Denial-of-service_attack](https://en.wikipedia.org/wiki/Denial-of-service_attack)
- **2**: [https://www.netscout.com/what-is-ddos/volumetric-attacks](https://www.netscout.com/what-is-ddos/volumetric-attacks)
- **3**: [https://www.scmagazine.com/brief/threat-intelligence/iranian-websites-impacted-by-pro-ukraine-ddos-attacks](https://www.scmagazine.com/brief/threat-intelligence/iranian-websites-impacted-by-pro-ukraine-ddos-attacks)
- **4**: [https://securityaffairs.com/53777/hacking/european-commission-eu.html](https://securityaffairs.com/53777/hacking/european-commission-eu.html)

## Description
Threat actors may wish to cause business disruption, media/public attention,
or to use the pretense of business disruption to disguise other activities. 
Any DDoS attack should always be followed up with other DFIR activities to 
determine if the attack was meant to distract from something else. DDoS can 
distract by pulling attention away, or even by spooling out log files so 
that relevant entries are overwritten.

## Criticality
**Emergency** - An Emergency priority incident poses an imminent threat to the provision of wide-scale critical infrastructure services, national government stability, or human lives.

## Terrain
> **Anything with Internet connectivity.

Domains: Enterprise, Networking, Private Cloud, Public Cloud, SaaS
Targets: API Endpoints, Serverless, Control Server, Web Application Servers, Public-Facing Servers
Platforms: AWS, Windows, Linux, Azure, Sysdig Backend, OVHcloud, Office 365, Kubernetes**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Business disruption; Operating costs; Reputational Damages | - |
| Leverage | Denial of Service | Threat action attempting to deny access to valid users, such as by making a web server temporarily unavailable or unusable. |
| Viability | Almost certain | Nearly certain - 95-99% |
| Kill Chain | Impact | Techniques aimed at manipulating, interrupting or destroying the target system or data. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT28](https://attack.mitre.org/groups/G0007) | `att&ck::G0007` | ('att&ck',) | [APT28](https://attack.mitre.org/groups/G0007) is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165.(Citation: NSA/FBI Drovorub August 2020)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021) This group has been active since at least 2004.(Citation: DOJ GRU Indictment Jul 2018)(Citation: Ars Technica GRU indictment Jul 2018)(Citation: Crowdstrike DNC June 2016)(Citation: FireEye APT28)(Citation: SecureWorks TG-4127)(Citation: FireEye APT28 January 2017)(Citation: GRIZZLY STEPPE JAR)(Citation: Sofacy DealersChoice)(Citation: Palo Alto Sofacy 06-2018)(Citation: Symantec APT28 Oct 2018)(Citation: ESET Zebrocy May 2019)  [APT28](https://attack.mitre.org/groups/G0007) reportedly compromised the Hillary Clinton campaign, the Democratic National Committee, and the Democratic Congressional Campaign Committee in 2016 in an attempt to interfere with the U.S. presidential election.(Citation: Crowdstrike DNC June 2016) In 2018, the US indicted five GRU Unit 26165 officers associated with [APT28](https://attack.mitre.org/groups/G0007) for cyber operations (including close-access operations) conducted between 2014 and 2018 against the World Anti-Doping Agency (WADA), the US Anti-Doping Agency, a US nuclear facility, the Organization for the Prohibition of Chemical Weapons (OPCW), the Spiez Swiss Chemicals Laboratory, and other organizations.(Citation: US District Court Indictment GRU Oct 2018) Some of these were conducted with the assistance of GRU Unit 74455, which is also referred to as [Sandworm Team](https://attack.mitre.org/groups/G0034). |
| APT28 | `misp::5b4ee3ea-eee3-4c8e-8323-85ae32658754` | ('misp',) | The Sofacy Group (also known as APT28, Pawn Storm, Fancy Bear and Sednit) is a cyber espionage group believed to have ties to the Russian government. Likely operating since 2007, the group is known to target government, military, and security organizations. It has been characterized as an advanced persistent threat. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1498` | [Network Denial of Service](https://attack.mitre.org/techniques/T1498) | Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)  A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on. For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet. This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).  To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets.  Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.  For DoS attacks targeting the hosting system directly, see [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499). |
