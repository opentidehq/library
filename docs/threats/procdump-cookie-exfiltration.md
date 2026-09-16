# ProcDump cookie exfiltration

## Metadata
| Field | Value |
| --- | --- |
| UUID | `e8761933-3137-41f7-bf7a-2687cac68524` |
| Schema | `threat::1.0` |
| Version | `1` |
| Created | `2024-11-05` |
| Modified | `2024-11-05` |
| TLP | clear (`TLP:CLEAR`) |
| Organisation | EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`) |

## References
### Public
- **1**: [https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies](https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies)
- **2**: [https://www.secureworks.com/blog/targeted-credential-theft](https://www.secureworks.com/blog/targeted-credential-theft)
- **3**: [https://learn.microsoft.com/en-us/sysinternals/downloads/procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)

## Description
Cookies can be found on disk and also in process memory. Additionally other 
applications on the targets machine might store sensitive authentication
tokens in memory (e.g. apps which authenticate to cloud services). 

ProcDump is a Sysinternal tool to dump strings from any process.

Using the example of the Firefox browser, an attacker can steal the browser 
cookies via ProcDump following the steps below:

  - Acquire the cookie from the user browser via process dump.
  - Exfiltrate the necessary authentication cookies.
  - Open Firefox on the attackers machine.
  - Navigate to the resource to access (the domain the cookie is valid for).
  - Use the Developer Console and set the cookie via document.cookie=“key=value”.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
Attacker must compromise a user endpoint and exfiltrate the browser cookies.
Cookies can be found on disk, in the process memory of the browser, and in
network traffic to remote systems.

## Surface
> **Microsoft::Microsoft 365**
> Microsoft 365 cloud-based productivity suite (formerly Office 365)

> **Azure::Security::Entra ID**
> Microsoft Entra ID in Azure (cloud identity)

> **OAuth / OIDC**
> OAuth 2.0 and OpenID Connect authorisation/authentication protocols

> **Azure**
> Microsoft Azure cloud platform

> **Windows::Desktop**
> Microsoft Windows desktop editions

> **Entra ID**
> Microsoft Entra ID (formerly Azure Active Directory)

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft<br>Impairement | Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.<br>Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery. |
| Leverage | Elevation of privilege<br>Spoofing | Capacity to augment leverage over the target system by upgrading the compromised access rights<br>Threat action aimed at accessing and use of another user’s credentials, such as username and password. |
| Viability | Environment dependent | Depends |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| UNC2452 | `misp::2ee5ed7a-c4d0-40be-a837-20817474a15b` | ('misp',) | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware. |
| [[Enterprise] Sandworm Team](https://attack.mitre.org/groups/G0034) | `att&ck::G0034` | ('att&ck',) | [Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)  In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018) |
| GreyEnergy | `misp::d52ca4c4-d214-11e8-8d29-c3e7cb78acce` | ('misp',) | ESET research reveals a successor to the infamous BlackEnergy APT group targeting critical infrastructure, quite possibly in preparation for damaging attacks |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1111` | [Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111) | Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.   If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. (Citation: Mandiant M Trends 2011)  Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). (Citation: GCN RSA June 2011)  Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users’ phones.(Citation: Okta Scatter Swine 2022) |

## Chaining
```mermaid
flowchart LR
subgraph "Credential Access"
e8761933_3137_41f7_bf7a_2687cac68524{{"ProcDump cookie<br>exfiltration"}}
ec8201d4_c135_406b_a3b5_4a070e80a2ee{{"Credential manipulation<br>on local Windows<br>endpoint"}}
b0d6bf74_b204_4a48_9509_4499ed795771{{"Pass-the-cookie Attack"}}
7351e2ca_e198_427c_9cfa_202df36f6e2a{{"Mimikatz execution on<br>compromised endpoint"}}
2d0beed6_6520_4114_be1f_24067628e93c{{"Manipulation of<br>credentials stored in<br>LSASS"}}
66aafb61_9a46_4287_8b40_4785b42b77a3{{"Adversary in the Middle<br>phishing sites to bypass<br>MFA"}}
4a807ac4_f764_41b1_ae6f_94239041d349{{"MFA Bypass Techniques"}}
end
subgraph "Lateral Movement"
5ea50181_1124_49aa_9d2c_c74103e86fd5{{"Pass-the-hash on SMB<br>network shares"}}
end
subgraph "Defense Evasion"
03cc9593_e7cf_484b_ae9c_684bf6f7199f{{"Pass the ticket using<br>Kerberos ticket"}}
end
subgraph "Privilege Escalation"
479a8b31_5f7e_4fd6_94ca_a5556315e1b8{{"Pass the hash using<br>impersonation within an<br>existing process"}}
4472e2b0_3dca_4d84_aab0_626fcba04fce{{"Pass the hash attack to<br>elevate privileges"}}
end
subgraph "Execution"
06523ed4_7881_4466_9ac5_f8417e972d13{{"Using a Windows command<br>prompt for credential<br>manipulation"}}
e3d7cb59_7aca_4c3d_b488_48c785930b6d{{"PowerShell usage for<br>credential manipulation"}}
a566e405_e9db_475f_8447_7875fa127716{{"Script execution on<br>Windows for credential<br>manipulation"}}
end
subgraph "Exploitation"
02311e3e_b7b8_4369_9e1e_74c0a844ae0f{{"NTLM credentials dumping<br>via SMB connection"}}
end
e8761933_3137_41f7_bf7a_2687cac68524 -->|succeeds| ec8201d4_c135_406b_a3b5_4a070e80a2ee
e8761933_3137_41f7_bf7a_2687cac68524 -->|implements| b0d6bf74_b204_4a48_9509_4499ed795771
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|succeeds| 5ea50181_1124_49aa_9d2c_c74103e86fd5
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|succeeds| 03cc9593_e7cf_484b_ae9c_684bf6f7199f
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|succeeds| 479a8b31_5f7e_4fd6_94ca_a5556315e1b8
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|succeeds| 4472e2b0_3dca_4d84_aab0_626fcba04fce
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|implements| 7351e2ca_e198_427c_9cfa_202df36f6e2a
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|implements| 06523ed4_7881_4466_9ac5_f8417e972d13
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|implements| e3d7cb59_7aca_4c3d_b488_48c785930b6d
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|implements| a566e405_e9db_475f_8447_7875fa127716
ec8201d4_c135_406b_a3b5_4a070e80a2ee -->|preceeds| 2d0beed6_6520_4114_be1f_24067628e93c
5ea50181_1124_49aa_9d2c_c74103e86fd5 -->|succeeds| 02311e3e_b7b8_4369_9e1e_74c0a844ae0f
b0d6bf74_b204_4a48_9509_4499ed795771 -->|succeeds| 66aafb61_9a46_4287_8b40_4785b42b77a3
b0d6bf74_b204_4a48_9509_4499ed795771 -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
66aafb61_9a46_4287_8b40_4785b42b77a3 -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
```
### Chaining details
#### succeeds -> [Credential manipulation on local Windows endpoint](credential-manipulation-on-local-windows-endpoint.md) (`ec8201d4-c135-406b-a3b5-4a070e80a2ee`) (`sequence::succeeds`)
Attacker must have a foot on the Windows enpoint to execute ProcDump.

- **Target UUID**: `ec8201d4-c135-406b-a3b5-4a070e80a2ee`
#### implements -> [Pass-the-cookie Attack](pass-the-cookie-attack.md) (`b0d6bf74-b204-4a48-9509-4499ed795771`) (`atomicity::implements`)
Technique used to steal browser cookies

- **Target UUID**: `b0d6bf74-b204-4a48-9509-4499ed795771`
