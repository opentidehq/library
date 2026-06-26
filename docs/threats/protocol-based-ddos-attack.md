# Protocol based DDoS attack

## Metadata

- **UUID**: `bc5aed0c-a2d1-4406-9a47-0721f3753a3b`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2023-01-26`
- **Modified**: `2023-02-03`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.imperva.com/learn/ddos/ddos-attacks/](https://www.imperva.com/learn/ddos/ddos-attacks/)
- **2**: [https://www.akamai.com/learn/what-are-syn-flood-ddos-attacks](https://www.akamai.com/learn/what-are-syn-flood-ddos-attacks)
- **3**: [https://www.f5.com/labs/learning-center/what-is-a-distributed-denial-of-service-attack](https://www.f5.com/labs/learning-center/what-is-a-distributed-denial-of-service-attack)

## Description
Threat actors may wish to cause business disruption, media/public attention, or to use the pretense of business disruption to disguise other activities. Any DDoS attack should always be followed up with other DFIR activities to determine if the attack was meant to distract from something else. DDoS can distract by pulling attention away, or even by spooling out log files so that relevant entries are overwritten.

## Criticality
**Emergency** - An Emergency priority incident poses an imminent threat to the provision of wide-scale critical infrastructure services, national government stability, or human lives.

## Terrain
> **Anything with Internet connectivity

Domains: Enterprise, Networking, Private Cloud, Public Cloud, SaaS
Targets: API Endpoints, Serverless, Control Server, Web Application Servers, Public-Facing Servers
Platforms: AWS, Azure, Apache HTTP Server, Confluence, JIRA, Microsoft SharePoint, MySQL, Network Router, NGINX, OVHcloud, Outlook Web Access, Postgress**

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
| `T1498.001` | [Network Denial of Service: Direct Network Flood](https://attack.mitre.org/techniques/T1498/001) | Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. [Direct Network Flood](https://attack.mitre.org/techniques/T1498/001)s are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well.  Botnets are commonly used to conduct network flooding attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global Internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for distributed DoS (DDoS), so many systems are used to generate the flood that each one only needs to send out a small amount of traffic to produce enough volume to saturate the target network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS flooding attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March 2016) |
