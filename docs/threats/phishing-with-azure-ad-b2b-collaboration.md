# Phishing with Azure AD B2B Collaboration

## Metadata

- **UUID**: `f9a6f927-d08c-40c1-85af-01331c471def`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2023-12-12`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://securepractice.co/blog/phishing-with-azure-ad-b2b-collaboration](https://securepractice.co/blog/phishing-with-azure-ad-b2b-collaboration)
- **2**: [https://learn.microsoft.com/en-us/entra/external-id/authentication-conditional-access](https://learn.microsoft.com/en-us/entra/external-id/authentication-conditional-access)
- **3**: [https://learn.microsoft.com/en-us/entra/external-id/invitation-email-elements](https://learn.microsoft.com/en-us/entra/external-id/invitation-email-elements)
- **4**: [https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf](https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf)

## Description
Phishing with Azure AD B2B Collaboration involves exploiting the service to send 
malicious invitations that appear to come from Microsoft or other third-parties,
making it difficult for the user to detect that it is not legitimate.
Here are the key points:

### Malicious Invitations 
Adversaries can create a free trial for Azure AD Premium and set up an Enterprise App 
with single sign-on (SSO) through a user-defined URL, which can be the adversary 
own website. This app can then be assigned to new users, allowing the adversaries to 
insert phishing recipients[1].

### Email Elements
The invitation email typically includes a warning about phishing, but the email 
itself appears legitimate. It is sent from a Microsoft address and includes a link 
to a landing page that may redirect users to the adversary site. The email may 
also include the inviter name and profile image for added credibility[3].

### Authentication Flow 
When a user accepts the invitation, they are redirected to the adversary site, 
may look like a legitimate Microsoft page. This can be achieved by creating an 
outdated OneDrive logo or using a well-known brand name in the Entra ID organization[1].

### Technical Details 
The phishing campaign can be set up using PowerShell commands to manage Azure AD 
and MSOnline modules. The adversaries can also use the Create invitation API to 
customize the invitation message and ensure it appears legitimate[2][4].

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries need administrative privileges or access to an existing Azure AD Premium account, or to create a new free trial account. After this, the capability to set up an Enterprise App with single sign-on through a user-defined URL, which can be their own website to deceive the user.

Domains: Public Cloud, Private Cloud, Enterprise, SaaS
Targets: Personal Information, End-user, Cloud Storage Accounts, Identity Services, Cloud Portal, Server Authentication, Remote access
Platforms: Windows, Office 365, Azure AD, Azure, PowerShell**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; IP Loss; Reputational Damages; Identity Theft; Competitive disadvantage; Business disruption; Lose Capabilities | - |
| Leverage | Spoofing; Infrastructure Compromise; Information Disclosure; New Accounts | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Social Engineering | Techniques aimed at the manipulation of people to perform unsafe actions. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| UNC2452 | `misp::2ee5ed7a-c4d0-40be-a837-20817474a15b` | ('misp',) | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1566` | [Phishing](https://attack.mitre.org/techniques/T1566) | Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.  Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source, as well as evasive techniques such as removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages (e.g., [Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008)).(Citation: Microsoft OAuth Spam 2022)(Citation: Palo Alto Unit 42 VBA Infostealer 2014) Another way to accomplish this is by [Email Spoofing](https://attack.mitre.org/techniques/T1672)(Citation: Proofpoint-spoof) the identity of the sender, which can be used to fool both the human recipient as well as automated security tools,(Citation: cyberproof-double-bounce) or by including the intended target as a party to an existing email thread that includes malicious files or links (i.e., "thread hijacking").(Citation: phishing-krebs)  Victims may also receive phishing messages that instruct them to call a phone number where they are directed to visit a malicious URL, download malware,(Citation: sygnia Luna Month)(Citation: CISA Remote Monitoring and Management Software) or install adversary-accessible remote management tools onto their computer (i.e., [User Execution](https://attack.mitre.org/techniques/T1204)).(Citation: Unit42 Luna Moth) |
