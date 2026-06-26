# Non-Approved container image deployed to run cryptominer

## Metadata

- **UUID**: `eca91e9a-616f-4439-ac03-5d0ecc2266df`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-06-29`
- **Modified**: `2022-06-29`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.securityweek.com/threat-actors-target-kubernetes-clusters-argo-workflows](https://www.securityweek.com/threat-actors-target-kubernetes-clusters-argo-workflows)
- **2**: [https://kubernetes.io/blog/2016/08/security-best-practices-kubernetes-deployment/](https://kubernetes.io/blog/2016/08/security-best-practices-kubernetes-deployment/)
- **3**: [https://www.stackrox.io/blog/kubernetes-security-101/](https://www.stackrox.io/blog/kubernetes-security-101/)

## Description
A threat actor can gain access to deployment workflows and pipelines and can then abuse acquired access to deploy images of their own choosing to deploy a cryptominer either directly via a malicious image, or by deploying a clean image first and then a cryptominer and C2 Infrastructure

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Running container clusters running in cloud, private cloud or in Enterprise Data Centre environments, potentially connected via a Continuous deployment tool

Domains: Public Cloud, Private Cloud, Enterprise
Targets: CI/CD Pipelines, Compute Cluster, Control Server, Development Pipelines
Platforms: AWS EC2, AWS EKS, AWS ECS, AWS Fargate, Azure AKS, VMware Tanzu, OVHcloud, IBM Cloud Kubernetes, Oracle Container Engine**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Substantial incident | A cyber attack which has a serious impact on a medium-sized organisation, or which poses a considerable risk to a large organisation or wider / local government. |
| Impact | Asset and fraud; Operating costs; Impairement | - |
| Leverage | Infrastructure Compromise; Dwelling; Software installation | - |
| Viability | Environment dependent | Depends |
| Kill Chain | Impact | Techniques aimed at manipulating, interrupting or destroying the target system or data. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] TeamTNT](https://attack.mitre.org/groups/G0139) | `att&ck::G0139` | ('att&ck',) | [TeamTNT](https://attack.mitre.org/groups/G0139) is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.(Citation: Palo Alto Black-T October 2020)(Citation: Lacework TeamTNT May 2021)(Citation: Intezer TeamTNT September 2020)(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro TeamTNT)(Citation: ATT TeamTNT Chimaera September 2020)(Citation: Aqua TeamTNT August 2020)(Citation: Intezer TeamTNT Explosion September 2021) |
| TeamTNT | `misp::27de6a09-844b-4dcb-9ff9-7292aad826ba` | ('misp',) | In early Febuary, 2021 TeamTNT launched a new campaign against Docker and Kubernetes environments. Using a collection of container images that are hosted in Docker Hub, the attackers are targeting misconfigured docker daemons, Kubeflow dashboards, and Weave Scope, exploiting these environments in order to steal cloud credentials, open backdoors, mine cryptocurrency, and launch a worm that is looking for the next victim. They're linked to the First Crypto-Mining Worm to Steal AWS Credentials and Hildegard Cryptojacking malware. TeamTNT is a relatively recent addition to a growing number of threats targeting the cloud. While they employ some of the same tactics as similar groups, TeamTNT stands out with their social media presence and penchant for self-promotion. Tweets from the TeamTNT’s account are in both English and German although it is unknown if they are located in Germany. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1610` | [Deploy Container](https://attack.mitre.org/techniques/T1610) | Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment. In Kubernetes environments, an adversary may attempt to deploy a privileged or vulnerable container into a specific node in order to [Escape to Host](https://attack.mitre.org/techniques/T1611) and access other containers running on the node. (Citation: AppSecco Kubernetes Namespace Breakout 2020)  Containers can be deployed by various means, such as via Docker's <code>create</code> and <code>start</code> APIs or via a web application such as the Kubernetes dashboard or Kubeflow. (Citation: Docker Containers API)(Citation: Kubernetes Dashboard)(Citation: Kubeflow Pipelines) In Kubernetes environments, containers may be deployed through workloads such as ReplicaSets or DaemonSets, which can allow containers to be deployed across multiple nodes.(Citation: Kubernetes Workload Management) Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime.(Citation: Aqua Build Images on Hosts) |
| `T1525` | [Implant Internal Image](https://attack.mitre.org/techniques/T1525) | Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike [Upload Malware](https://attack.mitre.org/techniques/T1608/001), this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)  A tool has been developed to facilitate planting backdoors in cloud container images.(Citation: Rhino Labs Cloud Backdoor September 2019) If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a [Web Shell](https://attack.mitre.org/techniques/T1505/003).(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019) |
| `T1496` | [Resource Hijacking](https://attack.mitre.org/techniques/T1496) | Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.   Resource hijacking may take a number of different forms. For example, adversaries may:  * Leverage compute resources in order to mine cryptocurrency * Sell network bandwidth to proxy networks * Generate SMS traffic for profit * Abuse cloud-based messaging services to send large quantities of spam messages  In some cases, adversaries may leverage multiple types of Resource Hijacking at once.(Citation: Sysdig Cryptojacking Proxyjacking 2023) |
