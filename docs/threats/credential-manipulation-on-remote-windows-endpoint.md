# Credential manipulation on remote Windows endpoint

## Metadata

- **UUID**: `cfc6369a-e3df-4827-bb0d-969342f1558c`
- **Schema**: `threat::1.0`
- **Version**: `6`
- **Created**: `2023-01-27`
- **Modified**: `2023-02-07`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://pypi.org/project/pypsexec/](https://pypi.org/project/pypsexec/)
- **2**: [https://stackoverflow.com/questions/24963625/psexec-run-python-script-passed-from-host](https://stackoverflow.com/questions/24963625/psexec-run-python-script-passed-from-host)
- **3**: [https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to/](https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to/)
- **4**: [https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/](https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/)
- **5**: [https://blogs.blackberry.com/en/2022/10/mustang-panda-abuses-legitimate-apps-to-target-myanmar-based-victims](https://blogs.blackberry.com/en/2022/10/mustang-panda-abuses-legitimate-apps-to-target-myanmar-based-victims)
- **6**: [https://learn.microsoft.com/en-us/sysinternals/downloads/psexec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- **7**: [https://www.sentinelone.com/cybersecurity-101/mimikatz/](https://www.sentinelone.com/cybersecurity-101/mimikatz/)
- **8**: [https://www.cisa.gov/uscert/ncas/alerts/aa22-011a](https://www.cisa.gov/uscert/ncas/alerts/aa22-011a)
- **9**: [https://resources.infosecinstitute.com/topic/apt-sandworm-notpetya-technical-overview/](https://resources.infosecinstitute.com/topic/apt-sandworm-notpetya-technical-overview/)
- **10**: [https://www.avertium.com/resources/threat-reports/in-depth-iranian-apt-muddywater](https://www.avertium.com/resources/threat-reports/in-depth-iranian-apt-muddywater)

## Description
Threat actors can perform credential manipulation on a remote Windows
endpoint with a variety of tools like: Mimikatz, WMIExec, WinRM-based,
PsExec, SMBExec or PowerShell or others to extract credentials from
a credential storage point on the endpoint, as example from the endpoint's
memory. This can be done by an attacker who already has gained access to
and control of one endpoint.

Requirements:

- permissions to access the remote machine
- permission/ability to run credential dumping tools
- or an ability to start a service remotely

Impacket PsExec example with username and password:

python3 psexec.py <domain>/<user>:<pass>@<target_host>

or an option with NTLM hashes

python3 psexec.py -hashes <lmhash>:<ntlmhash> <domain>/<user>@<target_host>

Example for Impacket SMBExec with plaintext credentials and NTLM hashes:

python3 smbexec.py "<domain>/<user>:<password>"@<target_host>

python3 smbexec.py -hashes <lmhash>:<ntlmhash> <domain>/<user>@<target_host>

Impacket suite contains a python script and can read the content of the
registry keys and decrypt the LSA Secrets passwords.

Example:

impacket-secretdump -sam /root/Desktop/sam.save -security /root/Desktop/security.save -system /root/Desktop/system.save LOCAL

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires an already compromised Windows endpoint.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: Workstations, Desktop, Laptop, End-user, Email Platform, Control Server, Remote access, System admin, Public-Facing Servers, Web Application Servers
Platforms: Windows, Active Directory, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Nuisance | Small and mostly inconsequential to day to day operations, but noticed. |
| Leverage | Tampering | Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Execution | Techniques that result in execution of attacker-controlled code on a local or remote system. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] Sandworm Team](https://attack.mitre.org/groups/G0034) | `att&ck::G0034` | ('att&ck',) | [Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)  In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018) |
| GreyEnergy | `misp::d52ca4c4-d214-11e8-8d29-c3e7cb78acce` | ('misp',) | ESET research reveals a successor to the infamous BlackEnergy APT group targeting critical infrastructure, quite possibly in preparation for damaging attacks |
| [[Enterprise] MuddyWater](https://attack.mitre.org/groups/G0069) | `att&ck::G0069` | ('att&ck',) | [MuddyWater](https://attack.mitre.org/groups/G0069) is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).(Citation: CYBERCOM Iranian Intel Cyber January 2022) Since at least 2017, [MuddyWater](https://attack.mitre.org/groups/G0069) has targeted a range of government and private organizations across sectors, including telecommunications, local government, defense, and oil and natural gas organizations, in the Middle East, Asia, Africa, Europe, and North America.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022) |
| MuddyWater | `misp::a29af069-03c3-4534-b78b-7d1a77ea085b` | ('misp',) | The MuddyWater attacks are primarily against Middle Eastern nations. However, we have also observed attacks against surrounding nations and beyond, including targets in India and the USA. MuddyWater attacks are characterized by the use of a slowly evolving PowerShell-based first stage backdoor we call “POWERSTATS”. Despite broad scrutiny and reports on MuddyWater attacks, the activity continues with only incremental changes to the tools and techniques. |
| [[Enterprise] Mustang Panda](https://attack.mitre.org/groups/G0129) | `att&ck::G0129` | ('att&ck',) | [Mustang Panda](https://attack.mitre.org/groups/G0129) is a China-based cyber espionage threat actor that was first observed in 2017 but may have been conducting operations since at least 2014. [Mustang Panda](https://attack.mitre.org/groups/G0129) has targeted government entities, nonprofits, religious, and other non-governmental organizations in the U.S., Europe, Mongolia, Myanmar, Pakistan, and Vietnam, among others.(Citation: Crowdstrike MUSTANG PANDA June 2018)(Citation: Anomali MUSTANG PANDA October 2019)(Citation: Secureworks BRONZE PRESIDENT December 2019) |
| RedDelta | `misp::fceed509-938e-4f9e-acd4-76e6c28dc6f1` | ('misp',) | Likely Chinese state-sponsored threat activity group RedDelta targeting organizations within Europe and Southeast Asia using a customized variant of the PlugX backdoor. Since at least 2019, RedDelta has been consistently active within Southeast Asia, particularly in Myanmar and Vietnam, but has also routinely adapted its targeting in response to global geopolitical events. This is historically evident through the group’s targeting of the Vatican and other Catholic organizations in the lead-up to 2021 talks between Chinese Communist Party (CCP) and Vatican officials, as well as throughout 2022 through the group’s shift towards increased targeting of European government and diplomatic entities following Russia’s invasion of Ukraine.  During the 3-month period from September through November 2022, RedDelta has regularly used an infection chain employing malicious shortcut (LNK) files, which trigger a dynamic-link library (DLL) search-order-hijacking execution chain to load consistently updated PlugX versions. Throughout this period, the group repeatedly employed decoy documents specific to government and migration policy within Europe. Of note, we identified a European government department focused on trade communicating with RedDelta command-and-control (C2) infrastructure in early August 2022. This activity commenced on the same day that a RedDelta PlugX sample using this C2 infrastructure and featuring an EU trade-themed decoy document surfaced on public malware repositories. We also identified additional probable victim entities within Myanmar and Vietnam regularly communicating with RedDelta C2 infrastructure.  RedDelta closely overlaps with public industry reporting under the aliases BRONZE PRESIDENT, Mustang Panda, TA416, Red Lich, and HoneyMyte. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1098.001` | [Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) | Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.  For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID.(Citation: Microsoft SolarWinds Customer Guidance)(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) These credentials include both x509 keys and passwords.(Citation: Microsoft SolarWinds Customer Guidance) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules.(Citation: Demystifying Azure AD Service Principals)  In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys using either the <code>CreateKeyPair</code> or <code>ImportKeyPair</code> API in AWS or the <code>gcloud compute os-login ssh-keys add</code> command in GCP.(Citation: GCP SSH Key Add) This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts.(Citation: Expel IO Evil in AWS)(Citation: Expel Behind the Scenes)  Adversaries may also use the <code>CreateAccessKey</code> API in AWS or the <code>gcloud iam service-accounts keys create</code> command in GCP to add access keys to an account. Alternatively, they may use the <code>CreateLoginProfile</code> API in AWS to add a password that can be used to log into the AWS Management Console for [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538).(Citation: Permiso Scattered Spider 2023)(Citation: Lacework AI Resource Hijacking 2024) If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)).(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Sysdig ScarletEel 2.0) For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator.(Citation: SpecterOps Azure Privilege Escalation)   In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to [Forge Web Credentials](https://attack.mitre.org/techniques/T1606) tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated. (Citation: Crowdstrike AWS User Federation Persistence)  In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account.(Citation: Mandiant APT42 Operations 2024) As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.(Citation: Microsoft Entra ID App Passwords) |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |
