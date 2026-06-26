# Pass the ticket using Kerberos ticket

## Metadata

- **UUID**: `03cc9593-e7cf-484b-ae9c-684bf6f7199f`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2022-09-23`
- **Modified**: `2025-10-01`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
- **2**: [https://www.netwrix.com/pass_the_ticket.html](https://www.netwrix.com/pass_the_ticket.html)
- **3**: [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- **4**: [https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1550-use-alternate-authentication-material/pass-the-ticket](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1550-use-alternate-authentication-material/pass-the-ticket)
- **5**: [https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html](https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html)
- **6**: [https://adsecurity.org/?p=2011](https://adsecurity.org/?p=2011)

## Description
Pass-the-Ticket using Kerberos tickets is an advanced method wherein threat 
actors illicitly extract and exploit Kerberos tickets to gain unauthorized 
access within a network. In the Kerberos authentication process, a Ticket 
Granting Ticket (TGT) is issued to users upon login. Adversaries involves 
the extraction of these Kerberos tickets through various means, such as 
leveraging vulnerabilities, utilizing tools like Mimikatz, or exploiting 
system weaknesses.   

Subsequently, adversaries misuse the acquired tickets to authenticate
themselves on other network systems without the need for the user's
password, allowing lateral movement and potential access to sensitive
information. Commonly employed tools, like Mimikatz and Rubeus,
facilitate these malicious activities.  

There are several types of possible TGT (ticket granting ticket)
authentication methods, for example:   

1. Credential theft technique permitting lateral movement, escalating
privileges, and gaining access to sensitive resources (TGT)  

2. Silver Ticket: Compromising Service Accounts with Kerberos Silver
Tickets (forged TGS for specific Services); The Silver ticket attack
is based on crafting a valid TGS for a service once the NTLM hash
of a user account is owned. In this case, the NTLM hash of a computer
account (which is kind of a user account in AD) is owned. Hence, it is
possible to craft a ticket in order to get into that machine with
administrator privileges through the SMB service. (ref [3])  

3. Golden Ticket: (forged TGTs) 
The Golden ticket technique is similar to the Silver ticket one,
but in this case a TGT is crafted by using the NTLM hash of the krbtgt
AD account. The advantage of forging a TGT instead of TGS is being able
to access any service (or machine) in the domain. (ref [3])    

### Tools

To carry out these attacks, adversaries use various types of tools,
such as:    

#### Mimikatz  

Commands:  

sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords

#### Rubeus  

Commands:  

\Rubeus.exe /ticket:base64blob
\Rubeus.exe ptt /ticket:BASE64BLOBHERE

#### Procdump  

Commands:  

procdump -ma lsass.exe lsass_dump  

The klist command that permit to see the Kerberos Tickets are the following:  

- Syntax: klist [-lh <logonID.highpart>] [-li <logonID.lowpart>] tickets | tgt | purge | sessions | kcd_cache | get | add_bind | query_bind | purge_bind
      * The syntax is related to Kerberos ticket management and credential cache management.

- Parameters:
    * -lh: Denotes the high part of the user's locally unique identifier (LUID), expressed in 
    hexadecimal. If neither -lh nor -li are present, the command defaults to the LUID of the 
    user who is currently signed in.
    * -li: Denotes the low part of the user's locally unique identifier (LUID), expressed in hexadecimal. 
    If neither -lh nor -li are present, the command defaults to the LUID of the user who is currently signed in.
    * tickets: Lists the currently cached ticket-granting-tickets (TGTs), and service tickets of the specified 
    logon session. This is the default option.
    * tgt: Displays the initial Kerberos TGT.
    * purge: Allows you to delete all the tickets of the specified logon session.
    * sessions: Displays a list of logon sessions on this computer.
    * kcd_cache: Displays the Kerberos constrained delegation cache information.
    * get: Allows you to request a ticket to the target computer specified by the service principal name (SPN).
    * add_bind: Allows you to specify a preferred domain controller for Kerberos authentication.
    * query_bind: Displays a list of cached preferred domain controllers for each domain that Kerberos has contacted.
    * purge_bind: Removes the cached preferred domain controllers for the domains specified.
    * kdcoptions: Displays the Key Distribution Center (KDC) options specified in RFC 4120.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries need to compromise an asset and be able to execute commands.

Domains: Enterprise
Targets: Auth token, End-user, Control Server, Workstations
Platforms: Windows, Active Directory**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Identity Theft; Business disruption; Data Breach | - |
| Leverage | Alter behavior; Elevation of privilege; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| UNC2452 | `misp::2ee5ed7a-c4d0-40be-a837-20817474a15b` | ('misp',) | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware. |
| [[Enterprise] APT32](https://attack.mitre.org/groups/G0050) | `att&ck::G0050` | ('att&ck',) | [APT32](https://attack.mitre.org/groups/G0050) is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journalists with a strong focus on Southeast Asian countries like Vietnam, the Philippines, Laos, and Cambodia. They have extensively used strategic web compromises to compromise victims.(Citation: FireEye APT32 May 2017)(Citation: Volexity OceanLotus Nov 2017)(Citation: ESET OceanLotus) |
| APT32 | `misp::aa29ae56-e54b-47a2-ad16-d3ab0242d5d7` | ('misp',) | Cyber espionage actors, now designated by FireEye as APT32 (OceanLotus Group), are carrying out intrusions into private sector companies across multiple industries and have also targeted foreign governments, dissidents, and journalists. FireEye assesses that APT32 leverages a unique suite of fully-featured malware, in conjunction with commercially-available tools, to conduct targeted operations that are aligned with Vietnamese state interests. |
| [[Enterprise] BRONZE BUTLER](https://attack.mitre.org/groups/G0060) | `att&ck::G0060` | ('att&ck',) | [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) is a cyber espionage group with likely Chinese origins that has been active since at least 2008. The group primarily targets Japanese organizations, particularly those in government, biotechnology, electronics manufacturing, and industrial chemistry.(Citation: Trend Micro Daserf Nov 2017)(Citation: Secureworks BRONZE BUTLER Oct 2017)(Citation: Trend Micro Tick November 2019) |
| Tick | `misp::add6554a-815a-4ac3-9b22-9337b9661ab8` | ('misp',) | Tick is a cyber espionage group with likely Chinese origins that has been active since at least 2008. The group appears to have close ties to the Chinese National University of Defense and Technology, which is possibly linked to the PLA. This threat actor targets organizations in the critical infrastructure, heavy industry, manufacturing, and international relations sectors for espionage purposes.  The attacks appear to be centered on political, media, and engineering sectors. STALKER PANDA has been observed conducting targeted attacks against Japan, Taiwan, Hong Kong, and the United States. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1550.003` | [Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) | Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.  When preforming PtT, valid Kerberos tickets for [Valid Accounts](https://attack.mitre.org/techniques/T1078) are captured by [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.(Citation: ADSecurity AD Kerberos Attacks)(Citation: GentilKiwi Pass the Ticket)  A [Silver Ticket](https://attack.mitre.org/techniques/T1558/002) can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).(Citation: ADSecurity AD Kerberos Attacks)  A [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.(Citation: Campbell 2014)  Adversaries may also create a valid Kerberos ticket using other user information, such as stolen password hashes or AES keys. For example, "overpassing the hash" involves using a NTLM password hash to authenticate as a user (i.e. [Pass the Hash](https://attack.mitre.org/techniques/T1550/002)) while also using the password hash to create a valid Kerberos ticket.(Citation: Stealthbits Overpass-the-Hash) |
