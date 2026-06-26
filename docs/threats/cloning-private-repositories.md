# Cloning private repositories

## Metadata

- **UUID**: `4ac2b666-736a-42c5-9548-50393ea6bc46`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-03-05`
- **Modified**: `2025-03-06`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://stackoverflow.com/questions/2505096/clone-a-private-repository-github](https://stackoverflow.com/questions/2505096/clone-a-private-repository-github)
- **2**: [https://www.educative.io/answers/how-to-clone-a-private-repository-from-github](https://www.educative.io/answers/how-to-clone-a-private-repository-from-github)
- **3**: [https://www.wwwinsights.com/webinfra/git/clone-a-github-private-repository/](https://www.wwwinsights.com/webinfra/git/clone-a-github-private-repository/)
- **4**: [https://cyberhoot.com/blog/github-config-breach-exposes-cloud-service-credentials](https://cyberhoot.com/blog/github-config-breach-exposes-cloud-service-credentials)
- **5**: [https://github.com/0xjesus/git-cloner](https://github.com/0xjesus/git-cloner)
- **6**: [https://github.com/scm-manager/scm-manager](https://github.com/scm-manager/scm-manager)
- **7**: [https://www.sentinelone.com/blog/exploiting-repos-6-ways-threat-actors-abuse-github-other-devops-platforms/](https://www.sentinelone.com/blog/exploiting-repos-6-ways-threat-actors-abuse-github-other-devops-platforms/)
- **8**: [https://sysdig.com/blog/emeraldwhale/](https://sysdig.com/blog/emeraldwhale/)

## Description
A threat actor can clone legit repositories, embed malicious code
but make them looks like legit. Their purpose is to entice a developer
to download and use the decoy repositories.    

Unauthorized cloning of private repositories is a form of IP theft.
Adversaries from external hackers to insiders aim to steal source code,
configuration details and secrets. The stolen information can be used
in multiple ways such as competitive advantage, discover vulnerabilities,
compromise other systems or mimic the original repositories to trick
developers into their rogue repository.  

After cloning of the repository, as a next step, the threat actor
spreads public available links from where a developer downloads its
malicious content.  

The threat actors employ various techniques to clone public or private
repositories, often with malicious intent. Some of the methods for
repository cloning include:  

### Misconfigured GitHub repositories

Threat actors exploit misconfigurations in GitHub, Gitlab or similar
repositories. They search for repositories with sensitive information
(such as API keys, credentials, or proprietary code) that have been
accidentally exposed. Once they find such repositories, they clone
them to their own accounts or local systems. By doing so, they gain
access to the codebase and any sensitive data within it ref [4].          

### Automated cloning and credential harvesting

In some cases, threat actors use automated tools to clone public
repositories. They specifically target repositories containing
Identity and Access Management (IAM) credentials. By cloning these
repositories, they harvest sensitive credentials, which can later
be used for unauthorized access, example in ref [5].            

### Repo confusion scheme

This scheme involves cloning existing repositories, Trojanizing them
(adding malicious code), and re-uploading them. The attackers hope that
the developers will mistakenly download the infected version.      

Once a threat actor has access to a CI pipeline, they obtain access key
or tokens to the SCM-Manager (ref [6]) and can perform action or operation
allowed for those credentials such as cloning private repository. This may
lead to unauthorized access to sensitive information and/or intellectual
property theft. Threat actors may identify weaknesses in the code and later
exploit them.      

A common command used for repositories cloning is:

git clone git://github.com/username/reponame.git

### Injection of a malicious code directly into exposed libraries

Some of the threat actor groups are observed to inject malicious code
directly into exposed libraries or submit fraudulent pull requests.
This technique can be used in a combination with repository cloning
to convey a malicious payload and infect developer systems and pilfer
sensitive files further ref [7].

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **The attacker needs to obtain access to the CI pipeline.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: CI/CD Pipelines, Code Repositories, Developer, Laptop
Platforms: Github, Gitlab, Bitbucket**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Localised incident | A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation. |
| Impact | Data Breach; Reputational Damages; Impairement | - |
| Leverage | Information Disclosure; Infrastructure Compromise | - |
| Viability | Environment dependent | Depends |
| Kill Chain | Exfiltration | Techniques that result or aid in an attacker removing data from a target network. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Lazarus Group](https://attack.mitre.org/groups/G0032) | `att&ck::G0032` | ('att&ck',) | [Lazarus Group](https://attack.mitre.org/groups/G0032) is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.(Citation: US-CERT HIDDEN COBRA June 2017)(Citation: Treasury North Korean Cyber Groups September 2019) The group has been active since at least 2009 and was reportedly responsible for the November 2014 destructive wiper attack against Sony Pictures Entertainment as part of a campaign named Operation Blockbuster by Novetta. Malware used by [Lazarus Group](https://attack.mitre.org/groups/G0032) correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.(Citation: Novetta Blockbuster)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups, such as [Andariel](https://attack.mitre.org/groups/G0138), [APT37](https://attack.mitre.org/groups/G0067), [APT38](https://attack.mitre.org/groups/G0082), and [Kimsuky](https://attack.mitre.org/groups/G0094). |
| Lazarus Group | `misp::68391641-859f-4a9a-9a1e-3e5cf71ec376` | ('misp',) | Since 2009, HIDDEN COBRA actors have leveraged their capabilities to target and compromise a range of victims; some intrusions have resulted in the exfiltration of data while others have been disruptive in nature. Commercial reporting has referred to this activity as Lazarus Group and Guardians of Peace. Tools and capabilities used by HIDDEN COBRA actors include DDoS botnets, keyloggers, remote access tools (RATs), and wiper malware. Variants of malware and tools used by HIDDEN COBRA actors include Destover, Duuzer, and Hangman. |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| APT29 | `misp::b2056ff0-00b9-482e-b11c-c771daa5f28a` | ('misp',) | A 2015 report by F-Secure describe APT29 as: 'The Dukes are a well-resourced, highly dedicated and organized cyberespionage group that we believe has been working for the Russian Federation since at least 2008 to collect intelligence in support of foreign and security policy decision-making. The Dukes show unusual confidence in their ability to continue successfully compromising their targets, as well as in their ability to operate with impunity. The Dukes primarily target Western governments and related organizations, such as government ministries and agencies, political think tanks, and governmental subcontractors. Their targets have also included the governments of members of the Commonwealth of Independent States;Asian, African, and Middle Eastern governments;organizations associated with Chechen extremism;and Russian speakers engaged in the illicit trade of controlled substances and drugs. The Dukes are known to employ a vast arsenal of malware toolsets, which we identify as MiniDuke, CosmicDuke, OnionDuke, CozyDuke, CloudDuke, SeaDuke, HammerDuke, PinchDuke, and GeminiDuke. In recent years, the Dukes have engaged in apparently biannual large - scale spear - phishing campaigns against hundreds or even thousands of recipients associated with governmental institutions and affiliated organizations. These campaigns utilize a smash - and - grab approach involving a fast but noisy breakin followed by the rapid collection and exfiltration of as much data as possible.If the compromised target is discovered to be of value, the Dukes will quickly switch the toolset used and move to using stealthier tactics focused on persistent compromise and long - term intelligence gathering. This threat actor targets government ministries and agencies in the West, Central Asia, East Africa, and the Middle East; Chechen extremist groups; Russian organized crime; and think tanks. It is suspected to be behind the 2015 compromise of unclassified networks at the White House, Department of State, Pentagon, and the Joint Chiefs of Staff. The threat actor includes all of the Dukes tool sets, including MiniDuke, CosmicDuke, OnionDuke, CozyDuke, SeaDuke, CloudDuke (aka MiniDionis), and HammerDuke (aka Hammertoss). ' |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1567.001` | [Exfiltration Over Web Service: Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001) | Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection.  Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network. |
