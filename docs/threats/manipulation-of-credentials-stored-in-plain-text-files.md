# Manipulation of credentials stored in plain text files

## Metadata

- **UUID**: `82dce94c-7b18-4cb9-bae0-56716b580418`
- **Schema**: `threat::1.0`
- **Version**: `3`
- **Created**: `2023-01-30`
- **Modified**: `2023-02-03`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://owasp.org/www-community/vulnerabilities/Password_Plaintext_Storage](https://owasp.org/www-community/vulnerabilities/Password_Plaintext_Storage)
- **2**: [https://www.digitalcitizen.life/which-windows-passwords-credentials-can-be-easily-cracked/](https://www.digitalcitizen.life/which-windows-passwords-credentials-can-be-easily-cracked/)
- **3**: [https://www.passcamp.com/blog/dangers-of-storing-and-sharing-passwords-in-plaintext/](https://www.passcamp.com/blog/dangers-of-storing-and-sharing-passwords-in-plaintext/)
- **4**: [https://dingtoffee.medium.com/clear-text-password-scanner-58fef77e4b2d](https://dingtoffee.medium.com/clear-text-password-scanner-58fef77e4b2d)
- **5**: [https://cwe.mitre.org/data/definitions/256.html](https://cwe.mitre.org/data/definitions/256.html)
- **6**: [https://cwe.mitre.org/data/definitions/312.html](https://cwe.mitre.org/data/definitions/312.html)
- **7**: [https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/#h2_4](https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/#h2_4)
- **8**: [https://thehackernews.com/2022/11/apt29-exploited-windows-feature-to.html](https://thehackernews.com/2022/11/apt29-exploited-windows-feature-to.html)
- **9**: [https://malpedia.caad.fkie.fraunhofer.de/actor/apt37](https://malpedia.caad.fkie.fraunhofer.de/actor/apt37)
- **10**: [https://know.netenrich.com/blog/fin6-know-your-threat-actor/](https://know.netenrich.com/blog/fin6-know-your-threat-actor/)
- **11**: [https://techcrunch.com/2022/03/23/microsoft-lapsus-hack-source-code/?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuYmluZy5jb20v&guce_referrer_sig=AQAAACu6oXda6fU_vTO_ITnANFi1ZPISubNID3kQVVIIRBVs66RYTxjTth2PCAn5DQkoUmnlR2cSzjKPPbVrUcJN1BWJpXhKL_I0Go8-xQeeROvzIhzNuEdbll2m7OY9PHeCnsjkIZJkUOrceGKkt6IAzdTE4MNMWs83kzZwWQa2UcdD](https://techcrunch.com/2022/03/23/microsoft-lapsus-hack-source-code/?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuYmluZy5jb20v&guce_referrer_sig=AQAAACu6oXda6fU_vTO_ITnANFi1ZPISubNID3kQVVIIRBVs66RYTxjTth2PCAn5DQkoUmnlR2cSzjKPPbVrUcJN1BWJpXhKL_I0Go8-xQeeROvzIhzNuEdbll2m7OY9PHeCnsjkIZJkUOrceGKkt6IAzdTE4MNMWs83kzZwWQa2UcdD)
- **12**: [https://www.fbi.gov/contact-us/field-offices/seattle/news/stories/how-cyber-crime-group-fin7-attacked-and-stole-data-from-hundreds-of-us-companies](https://www.fbi.gov/contact-us/field-offices/seattle/news/stories/how-cyber-crime-group-fin7-attacked-and-stole-data-from-hundreds-of-us-companies)

## Description
Threat actors are searching for credentials stored in plain text, usually in
an application's properties, configuration files, system memory or other
places in the system. Storing a plain text password could lead to data
leakage because, for example when the passwords are stored in clear text
in a configuration file everyone who has read access to the file can see
and steal the passwords. In most cases, even storage of a plaintext
password in a memory is considered as a security risk if the password
is not cleared immediately after it is used. Good password management
policies require that a password shouldn't be stored in a plaintext.

In some cases the user's passwords are stored in plain text when a program
application or system file crates and saves them automatically in a file
without encryption. In other cases the credentials can be stored in clear 
text by user's mistake. Threat actors are using different methods like:
password cracking, dictionary attack, social engineering and phishing
attacks, man in the middle attack, malware injections and others to steal
and manipulate credentials stored in a plain text.

One example of manipulation of credentials stored in plain text files is by
using a technique called "password cracking." This involves using a computer
program to repeatedly guess a password or its hash until the correct one is
found. If the plain text file containing the credentials is not properly
secured, an attacker could gain access to sensitive information such as
username and password combinations. Threat actors are using variety of
different tools to crack user's credentials, for example: John the Ripper,
Hashcat, Aircrack-ng, Cain and Abel, Mimikatz, custom python scripts and
others. 

Example for a code that reads a password from a properties file and uses
the password to connect to a database:

Properties prop = new Properties();
prop.load(new FileInputStream("config.properties"));
String password = prop.getProperty("password");

DriverManager.getConnection(url, usr, password);

Example for a python script scanning for files stored in a clear text:

# put your path here 
# Network SMB path you want to search 
root_dir = ("xxxxxx", "etc.")
# location where you want to put the result 
stored_dir = 'xxxxxxxxx'
# exception you want to filter
exception_path = ["snapshot"]

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor is using an already compromised Windows endpoint.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: End-user, Desktop, Laptop, Workstations, Control Server, Remote access, System admin, Developer, Production Database, Public-Facing Servers, Web Application Servers
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Nuisance | Small and mostly inconsequential to day to day operations, but noticed. |
| Leverage | Tampering | Threat action intending to maliciously change or modify persistent data, such as records in a database, and the alteration of data in transit between two computers over an open network, such as the Internet. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| UNC2452 | `misp::2ee5ed7a-c4d0-40be-a837-20817474a15b` | ('misp',) | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware. |
| [[Enterprise] APT37](https://attack.mitre.org/groups/G0067) | `att&ck::G0067` | ('att&ck',) | [APT37](https://attack.mitre.org/groups/G0067) is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, India, Romania, Kuwait, and other parts of the Middle East. [APT37](https://attack.mitre.org/groups/G0067) has also been linked to the following campaigns between 2016-2018: Operation Daybreak, Operation Erebus, Golden Time, Evil New Year, Are you Happy?, FreeMilk, North Korean Human Rights, and Evil New Year 2018.(Citation: FireEye APT37 Feb 2018)(Citation: Securelist ScarCruft Jun 2016)(Citation: Talos Group123)  North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups. |
| APT37 | `misp::50cd027f-df14-40b2-aa22-bf5de5061163` | ('misp',) | APT37 has likely been active since at least 2012 and focuses on targeting the public and private sectors primarily in South Korea. In 2017, APT37 expanded its targeting beyond the Korean peninsula to include Japan, Vietnam and the Middle East, and to a wider range of industry verticals, including chemicals, electronics, manufacturing, aerospace, automotive and healthcare entities |
| [[Enterprise] FIN6](https://attack.mitre.org/groups/G0037) | `att&ck::G0037` | ('att&ck',) | [FIN6](https://attack.mitre.org/groups/G0037) is a cyber crime group that has stolen payment card data and sold it for profit on underground marketplaces. This group has aggressively targeted and compromised point of sale (PoS) systems in the hospitality and retail sectors.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019) |
| FIN6 | `misp::647894f6-1723-4cba-aba4-0ef0966d5302` | ('misp',) | FIN is a group targeting financial assets including assets able to do financial transaction including PoS. |
| [[Enterprise] LAPSUS$](https://attack.mitre.org/groups/G1004) | `att&ck::G1004` | ('att&ck',) | [LAPSUS$](https://attack.mitre.org/groups/G1004) is cyber criminal threat group that has been active since at least mid-2021. [LAPSUS$](https://attack.mitre.org/groups/G1004) specializes in large-scale social engineering and extortion operations, including destructive attacks without the use of ransomware. The group has targeted organizations globally, including in the government, manufacturing, higher education, energy, healthcare, technology, telecommunications, and media sectors.(Citation: BBC LAPSUS Apr 2022)(Citation: MSTIC DEV-0537 Mar 2022)(Citation: UNIT 42 LAPSUS Mar 2022) |
| LAPSUS | `misp::d9e5be22-1a04-4956-af6c-37af02330980` | ('misp',) | An actor group conducting large-scale social engineering and extortion campaign against multiple organizations with some seeing evidence of destructive elements. |
| [[Enterprise] FIN7](https://attack.mitre.org/groups/G0046) | `att&ck::G0046` | ('att&ck',) | [FIN7](https://attack.mitre.org/groups/G0046) is a financially-motivated threat group that has been active since 2013. [FIN7](https://attack.mitre.org/groups/G0046) has primarily targeted the retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud services, media, food and beverage, transportation, and utilities industries in the U.S. A portion of [FIN7](https://attack.mitre.org/groups/G0046) was run out of a front company called Combi Security and often used point-of-sale malware for targeting efforts. Since 2020, [FIN7](https://attack.mitre.org/groups/G0046) shifted operations to a big game hunting (BGH) approach including use of [REvil](https://attack.mitre.org/software/S0496) ransomware and their own Ransomware as a Service (RaaS), Darkside. FIN7 may be linked to the [Carbanak](https://attack.mitre.org/groups/G0008) Group, but there appears to be several groups using [Carbanak](https://attack.mitre.org/software/S0030) malware and are therefore tracked separately.(Citation: FireEye FIN7 March 2017)(Citation: FireEye FIN7 April 2017)(Citation: FireEye CARBANAK June 2017)(Citation: FireEye FIN7 Aug 2018)(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022) |
| FIN7 | `misp::00220228-a5a4-4032-a30d-826bb55aa3fb` | ('misp',) | Groups targeting financial organizations or people with significant financial assets. |
| [[Enterprise] Wizard Spider](https://attack.mitre.org/groups/G0102) | `att&ck::G0102` | ('att&ck',) | [Wizard Spider](https://attack.mitre.org/groups/G0102) is a Russia-based financially motivated threat group originally known for the creation and deployment of [TrickBot](https://attack.mitre.org/software/S0266) since at least 2016. [Wizard Spider](https://attack.mitre.org/groups/G0102) possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.(Citation: CrowdStrike Ryuk January 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: CrowdStrike Wizard Spider October 2020) |
| UNC1878 | `misp::3c2bb7d7-a085-4594-adc7-4a20cf724abb` | ('misp',) | UNC1878 is a financially motivated threat actor that monetizes network access via the deployment of RYUK ransomware. Earlier this year, Mandiant published a blog on a fast-moving adversary deploying RYUK ransomware, UNC1878. Shortly after its release, there was a significant decrease in observed UNC1878 intrusions and RYUK activity overall almost completely vanishing over the summer. But beginning in early fall, Mandiant has seen a resurgence of RYUK along with TTP overlaps indicating that UNC1878 has returned from the grave and resumed their operations. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1552` | [Unsecured Credentials](https://attack.mitre.org/techniques/T1552) | Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)),  or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).(Citation: Brining MimiKatz to Unix) |
| `T1565` | [Data Manipulation](https://attack.mitre.org/techniques/T1565) | Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data.(Citation: Sygnia Elephant Beetle Jan 2022) By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.  The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact. |
| `T1003` | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.  Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well. |
| `T1555.003` | [Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) | Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.  For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key.(Citation: Microsoft CryptUnprotectData April 2018)   Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc.(Citation: Proofpoint Vega Credential Stealer May 2018)(Citation: FireEye HawkEye Malware July 2017) Windows stores Internet Explorer and Microsoft Edge credentials in Credential Lockers managed by the [Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004).  Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials.(Citation: GitHub Mimikittenz July 2016)  After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator). |
| `T1110.002` | [Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002) | Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Further,  adversaries may leverage [Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) in order to obtain hashed credentials for network devices.(Citation: US-CERT-TA18-106A)   Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network.(Citation: Wikipedia Password cracking) The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access. |
| `T1003.007` | [OS Credential Dumping: Proc Filesystem](https://attack.mitre.org/techniques/T1003/007) | Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc/<PID>/maps` file shows how memory is mapped within the process’s virtual address space. And `/proc/<PID>/mem`, exposed for debugging purposes, provides access to the process’s virtual address space.(Citation: Picus Labs Proc cump 2022)(Citation: baeldung Linux proc map 2022)  When executing with root privileges, adversaries can search these memory locations for all processes on a system that contain patterns indicative of credentials. Adversaries may use regex patterns, such as <code>grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps \| cut -d' ' -f 1</code>, to look for fixed strings in memory structures or cached hashes.(Citation: atomic-red proc file system) When running without privileged access, processes can still view their own virtual memory locations. Some services or programs may save credentials in clear text inside the process’s memory.(Citation: MimiPenguin GitHub May 2017)(Citation: Polop Linux PrivEsc Gitbook)  If running as or with the permissions of a web browser, a process can search the `/maps` & `/mem` locations for common website credential patterns (that can also be used to find adjacent memory within the same structure) in which hashes or cleartext credentials may be located. |
