# Social engineering attack using Microsoft Teams

## Metadata

- **UUID**: `06c60af1-5fa8-493c-bf9b-6b2e215819f1`
- **Schema**: `threat::1.0`
- **Version**: `4`
- **Created**: `2023-08-07`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/](https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/)
- **2**: [https://github.com/Octoberfest7/TeamsPhisher](https://github.com/Octoberfest7/TeamsPhisher)

## Description
Adversaries are using compromised Microsoft 365 tenants to create technical
support-themed domains and send tech support lures via Microsoft Teams, 
attempting to trick users of the targeted organizations using social engineering.    

They aim to manipulate users into granting approval for multifactor authentication
(MFA) prompts, ultimately aiming to steal their credentials.    

#### Attack phases    

**Preparation phase**    

Attackers compromise an Azure tenant, rename it and add a new onmicrosoft[.]com
subdomain. It will use security-themed or product name-themed keywords to create
a new subdomain, such as teamsprotection.onmicrosoft[.]com 
Add a new user associated with that domain from which the attacker will send the
outbound message to the target tenant.    

**Social engineering phase**    

Attackers send a Teams chat message to the target from the compromised external user
masquerading as a technical support or security team; if the targeted user accepts
the message request, attackers send a Microsoft Teams message to convince the target
to enter a code into the Microsoft Authenticator app on his/her mobile device.
If the targeted user enters the code into the Authenticator app, the attacker is
granted a token to authenticate as the targeted user.    

**Post-compromise phase**    

Involves information theft from the compromised Microsoft 365 tenant, and in some 
cases, adding a device to the organisation as a managed device through Microsoft
Entra ID (formerly Azure Active Directory), likely an attempt to circumvent conditional
access policies configured to restrict access to specific resources to managed devices only.    

#### Additional Tactics: Microsoft Teams Vishing    

### Microsoft Teams Vishing    

- Attackers initiate contact via Microsoft Teams within 15-30 minutes of the email bombing.
- They pose as IT support personnel or "Help Desk Managers".
- Adversary-controlled Office 365 accounts are used, often with display names mimicking 
legitimate IT staff.
- Profile pictures and backgrounds are crafted to appear authentic.
- Attackers exploit the victim's state of confusion and urgency caused by the email bombing.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Attacker has compromised a valid Microsoft 365 tenant to host the lures, and valid
valid credentials in targeted M365 tenant too.
Targeted organizations must use an app like Microsoft Authenticator as second
factor (app taking the code received after successful authentication granted by 
the victim, the user, in previous step).

Domains: Enterprise, Private Cloud, Public Cloud
Targets: End-user
Platforms: Microsoft Teams**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft; Data Breach | - |
| Leverage | Information Disclosure | Threat action intending to read a file that one was not granted access to, or to read data in transit. |
| Viability | Environment dependent | Depends |
| Kill Chain | Delivery | Techniques resulting in the transmission of a weaponized object to the targeted environment. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| UNC2452 | `misp::2ee5ed7a-c4d0-40be-a837-20817474a15b` | ('misp',) | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1199` | [Trusted Relationship](https://attack.mitre.org/techniques/T1199) | Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.  Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, [Valid Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to internal network systems may be compromised and used.(Citation: CISA IT Service Providers)  In Office 365 environments, organizations may grant Microsoft partners or resellers delegated administrator permissions. By compromising a partner or reseller account, an adversary may be able to leverage existing delegated administrator relationships or send new delegated administrator offers to clients in order to gain administrative control over the victim tenant.(Citation: Office 365 Delegated Administration) |
