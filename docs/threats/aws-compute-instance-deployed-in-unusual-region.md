# AWS Compute instance deployed in unusual region

## Metadata

- **UUID**: `1040ebd2-4659-4844-9238-95fa69a7e63c`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-12-12`
- **Modified**: `2022-12-12`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e](https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e)
- **2**: [https://www.techradar.com/news/upgraded-crypto-mining-malware-now-steals-aws-credentials](https://www.techradar.com/news/upgraded-crypto-mining-malware-now-steals-aws-credentials)
- **3**: [https://cybersecurityworldconference.com/2022/01/13/threat-actors-abuse-public-cloud-services-to-spread-multiple-rats/](https://cybersecurityworldconference.com/2022/01/13/threat-actors-abuse-public-cloud-services-to-spread-multiple-rats/)
- **4**: [https://sysdig.com/blog/teamtnt-aws-credentials/](https://sysdig.com/blog/teamtnt-aws-credentials/)
- **5**: [https://lantern.splunk.com/Security/Use_Cases/Threat_Hunting/Detecting_suspicious_new_instances_in_your_AWS_EC2_environment](https://lantern.splunk.com/Security/Use_Cases/Threat_Hunting/Detecting_suspicious_new_instances_in_your_AWS_EC2_environment)

## Description
Certain threat actors will try to launch AWS compute instances 
(EC2, EKS, ECS) instances to achieve their objectives

One of the main vectors currently is to monetize access to 
privileged AWS credentials by deploying new compute instances of various types 
to mine cryptocurrencies. To hide their deployed instances, a threat actor 
may deploying the resources into unused regions, where they may go 
unnoticed.

Additionally threat actor may launch compute instances to act as staging 
platforms for serving malware for other campaigns.

It is expected that threat actors will potentially use compute instances 
for other purposes than the 2 listed above.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Attacker needs to control credentials required to deploy an EC2 instance,
or to deploy a compute resource of a type that runs on EC2.

Domains: Public Cloud
Targets: IaaS
Platforms: AWS EC2, AWS ECS, AWS EKS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Localised incident | A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation. |
| Impact | Operating costs; Asset and fraud; Legal and regulatory | - |
| Leverage | Software installation; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Impact | Techniques aimed at manipulating, interrupting or destroying the target system or data. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] TeamTNT](https://attack.mitre.org/groups/G0139) | `att&ck::G0139` | ('att&ck',) | [TeamTNT](https://attack.mitre.org/groups/G0139) is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.(Citation: Palo Alto Black-T October 2020)(Citation: Lacework TeamTNT May 2021)(Citation: Intezer TeamTNT September 2020)(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro TeamTNT)(Citation: ATT TeamTNT Chimaera September 2020)(Citation: Aqua TeamTNT August 2020)(Citation: Intezer TeamTNT Explosion September 2021) |
| TeamTNT | `misp::27de6a09-844b-4dcb-9ff9-7292aad826ba` | ('misp',) | In early Febuary, 2021 TeamTNT launched a new campaign against Docker and Kubernetes environments. Using a collection of container images that are hosted in Docker Hub, the attackers are targeting misconfigured docker daemons, Kubeflow dashboards, and Weave Scope, exploiting these environments in order to steal cloud credentials, open backdoors, mine cryptocurrency, and launch a worm that is looking for the next victim. They're linked to the First Crypto-Mining Worm to Steal AWS Credentials and Hildegard Cryptojacking malware. TeamTNT is a relatively recent addition to a growing number of threats targeting the cloud. While they employ some of the same tactics as similar groups, TeamTNT stands out with their social media presence and penchant for self-promotion. Tweets from the TeamTNT’s account are in both English and German although it is unknown if they are located in Germany. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1496` | [Resource Hijacking](https://attack.mitre.org/techniques/T1496) | Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.   Resource hijacking may take a number of different forms. For example, adversaries may:  * Leverage compute resources in order to mine cryptocurrency * Sell network bandwidth to proxy networks * Generate SMS traffic for profit * Abuse cloud-based messaging services to send large quantities of spam messages  In some cases, adversaries may leverage multiple types of Resource Hijacking at once.(Citation: Sysdig Cryptojacking Proxyjacking 2023) |
