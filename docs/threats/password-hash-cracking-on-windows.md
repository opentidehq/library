# Password hash cracking on Windows

## Metadata

- **UUID**: `35c76d6c-2ac7-486e-b0b7-b56f6b110bec`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2023-02-03`
- **Modified**: `2023-02-06`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://robertscocca.medium.com/cracking-windows-hashes-fb0af3108c0a](https://robertscocca.medium.com/cracking-windows-hashes-fb0af3108c0a)
- **2**: [https://securitygladiators.com/security/software/password-cracker/](https://securitygladiators.com/security/software/password-cracker/)
- **3**: [https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/](https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/)
- **4**: [https://medium.com/cyber-security-resources/hacking-and-cracking-ntlm-hash-to-get-windows-admin-password-f44819b01db5](https://medium.com/cyber-security-resources/hacking-and-cracking-ntlm-hash-to-get-windows-admin-password-f44819b01db5)
- **5**: [https://www.thehacker.recipes/ad/movement/credentials/cracking](https://www.thehacker.recipes/ad/movement/credentials/cracking)
- **6**: [https://www.softwaretestinghelp.com/password-cracker-tools/](https://www.softwaretestinghelp.com/password-cracker-tools/)
- **7**: [https://www.freecodecamp.org/news/hacking-with-hashcat-a-practical-guide/](https://www.freecodecamp.org/news/hacking-with-hashcat-a-practical-guide/)
- **8**: [https://crackstation.net/](https://crackstation.net/)
- **9**: [https://download.cnet.com/Password-Cracker/3000-2092_4-10226556.html](https://download.cnet.com/Password-Cracker/3000-2092_4-10226556.html)
- **10**: [https://www.darknet.org.uk/2006/09/brutus-password-cracker-download-brutus-aet2zip-aet2/](https://www.darknet.org.uk/2006/09/brutus-password-cracker-download-brutus-aet2zip-aet2/)
- **11**: [https://www.softpedia.com/get/Security/Encrypting/RainbowCrack.shtml](https://www.softpedia.com/get/Security/Encrypting/RainbowCrack.shtml)
- **12**: [https://sourceforge.net/projects/thc-hydra.mirror/](https://sourceforge.net/projects/thc-hydra.mirror/)
- **13**: [https://www.cyberpratibha.com/cain-and-abel-software-cracking-hashes/](https://www.cyberpratibha.com/cain-and-abel-software-cracking-hashes/)
- **14**: [https://l0phtcrack.gitlab.io/](https://l0phtcrack.gitlab.io/)
- **15**: [https://www.pwndefend.com/2021/10/18/password-auditing-with-l0phtcrack-7-a-quick-intro/](https://www.pwndefend.com/2021/10/18/password-auditing-with-l0phtcrack-7-a-quick-intro/)

## Description
Threat actors often extract valid credentials from target systems. When
these credentials are in a hashed format, threat actors may use different
methods to crack and obtain the credentials in clear text. When this
information cannot be directly leveraged for higher privileges (like with
pass-the-hash, overpass-the-hash), it is required to crack it. Some methods
that threat actors use include: brute force, dictionary attack, or sub-set
of the dictionary attack named rainbow tables. Threat actors can use
a variety of tools to crack password hashes. For example,
Mimikatz, Hashcat, CrackStation, Password Cracker, Brutus Password Cracker,
Aircrack, THC Hydra, RainbowCrack, Cain and Abel, Medusa, John The Ripper,
ophCrack, WFuzz, L0phtCrack, OphCrack and others.

The threat actors can crack the password hashes, for example with JTR or
Hashcat cracking tools that use text files to match and crack the hashes. 
(an example for a text file could be: rockyou.txt)

gunzip /usr/share/wordlist/file.txt
john hash.txt /usr/share/wordlists/file.txt — format=nt

hashcat -m 1000 hash.txt /usr/share/wordlists/file.txt

An example of how to use Hashcat for a dictionary attack:

hashcat --attack-mode 0 --hash-type $number $hashes_file $wordlist_file

OR 

hashcat --loopback --attack-mode 0 --rules-file $rules_file --hash-type $number $hashes_file $wordlist_file

Example for Hashcat tool which can bruteforce any password from 4 to 8
characters long:

hashcat --attack-mode 3 --increment --increment-min 4 --increment-max 8 --hash-type $number $hashes_file "file"

Hashcat can also be started with custom charsets:

hashcat --attack-mode 3 --custom-charset1 "?u" --custom-charset2 "?l?u?d" --custom-charset3 "?d" --hash-type $number $hashes_file "file"

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor is using already compromised Windows endpoint.

Domains: Enterprise, Private Cloud, Public Cloud
Targets: Desktop, Laptop, Workstations, Control Server, Remote access, System admin, Public-Facing Servers, Web Application Servers, Production Database
Platforms: Windows, Active Directory**

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
| [[Enterprise] FIN6](https://attack.mitre.org/groups/G0037) | `att&ck::G0037` | ('att&ck',) | [FIN6](https://attack.mitre.org/groups/G0037) is a cyber crime group that has stolen payment card data and sold it for profit on underground marketplaces. This group has aggressively targeted and compromised point of sale (PoS) systems in the hospitality and retail sectors.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019) |
| FIN6 | `misp::647894f6-1723-4cba-aba4-0ef0966d5302` | ('misp',) | FIN is a group targeting financial assets including assets able to do financial transaction including PoS. |
| [[Enterprise] Dragonfly](https://attack.mitre.org/groups/G0035) | `att&ck::G0035` | ('att&ck',) | [Dragonfly](https://attack.mitre.org/groups/G0035) is a cyber espionage group that has been attributed to Russia's Federal Security Service (FSB) Center 16.(Citation: DOJ Russia Targeting Critical Infrastructure March 2022)(Citation: UK GOV FSB Factsheet April 2022) Active since at least 2010, [Dragonfly](https://attack.mitre.org/groups/G0035) has targeted defense and aviation companies, government entities, companies related to industrial control systems, and critical infrastructure sectors worldwide through supply chain, spearphishing, and drive-by compromise attacks.(Citation: Symantec Dragonfly)(Citation: Secureworks IRON LIBERTY July 2019)(Citation: Symantec Dragonfly Sept 2017)(Citation: Fortune Dragonfly 2.0 Sept 2017)(Citation: Gigamon Berserk Bear October 2021)(Citation: CISA AA20-296A Berserk Bear December 2020)(Citation: Symantec Dragonfly 2.0 October 2017) |
| ENERGETIC BEAR | `misp::64d6559c-6d5c-4585-bbf9-c17868f763ee` | ('misp',) | A Russian group that collects intelligence on the energy industry. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1110.002` | [Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002) | Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Further,  adversaries may leverage [Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) in order to obtain hashed credentials for network devices.(Citation: US-CERT-TA18-106A)   Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network.(Citation: Wikipedia Password cracking) The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access. |
