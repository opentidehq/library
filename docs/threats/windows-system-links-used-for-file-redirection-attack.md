# Windows system links used for file redirection attack

## Metadata

- **UUID**: `9fc6fdcd-c06e-4f7b-8562-a6753d8be683`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2024-04-24`
- **Modified**: `2024-06-25`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://unit42.paloaltonetworks.com/junctions-windows-redirection-trust-mitigation/](https://unit42.paloaltonetworks.com/junctions-windows-redirection-trust-mitigation/)
- **2**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0787_bits_arbitrary_file_move.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/cve_2020_0787_bits_arbitrary_file_move.rb)
- **3**: [https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0787/](https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0787/)

## Description
By using different types of file system links, such as hard links or junctions, 
attackers can trick the privileged component into operating on files which is 
not supposed to access. The end goal for such attacks is usually to write an 
attacker-supplied executable (such as a DLL or a script) to the disk, 
and to get it executed with system permissions (ref \[1\]).  

For example, to achieve code execution as the SYSTEM user, threat actors start 
an orchestrator update service, which will result in a malicious DLL being run 
with SYSTEM privileges due to a DLL hijacking issue within the Update Session 
Orchestrator Service. (ref \[2\])  

The most common file redirection links are:

##### LNK files (shortcut files)

These are files with the .LNK extension, which are used to create shortcuts to 
other files or folders. Attackers can exploit LNK files to execute malicious 
code by creating a shortcut that points to a malicious file instead of the original 
intended target.  

##### Junction points

Junction points are special folders in Windows that link to another folder, allowing 
the operating system to treat the content of the target folder as if they were 
located in the junction point's folder. Attackers can use junction points to redirect 
file access to a different location, potentially allowing them to access or modify 
files that should not be accessible.  

Junctions are a feature of the NT file system (NTFS) that make it possible to link one 
directory into another. They are used by default, linking some directories such as 
"C:\\Documents and Settings".  

A common vulnerable pattern may exist in the hard (junction) links as follows 
(for example CVE-2020-0787):

* A privileged service exposes functionality that can be triggered through some 
interprocess communication (IPC) mechanism, such as remote procedure call (RPC). 
That functionality can be triggered by users running at lower privilege levels.  
* That functionality operates on a file (writing data into that file) that is 
located under a globally writable directory. The operation is done without 
impersonation, meaning it occurs with the permissions of that system service.  

To exploit this vulnerability in the system links a threat actor first creates a junction 
between that directory and their target, which is usually C:\\Windows or one of its 
subdirectories. Next, the attacker triggers the RPC call, which follows the junction to 
overwrite a system DLL file. Finally, that malicious DLL is loaded by some service, 
and the attacker's supplied code gets executed with system permissions (ref \[1\]).  

##### Symbolic links:

Symbolic links (also known as symlinks or soft links) are similar to junction points, 
but they can link to individual files as well as folders. Symbolic links can be used to 
redirect file access to a different file or folder, which may allow an attacker to 
execute malicious code or access sensitive information.  

##### NTFS Alternate Data Streams (ADS):

Alternate Data Streams are a feature of the NTFS file system that allows storing 
metadata within a file. Attackers can abuse ADS to hide malicious code or sensitive 
information within an innocent-looking file. When the file is accessed, the malicious 
content in the ADS is executed without the user's knowledge.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor needs an initial access to the system with 
standard user rights.

Domains: Enterprise
Cve: CVE-2020-0787
Targets: Workstations, Control Server, End-user, Desktop, Directory, Remote access, System admin
Platforms: Windows, Azure AD, Active Directory**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Localised incident | A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation. |
| Impact | Impairement; Nuisance; Data Breach; Reputational Damages | - |
| Leverage | Infrastructure Compromise; Dwelling; Elevation of privilege; Tampering | - |
| Viability | Environment dependent | Depends |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1562` | [Impair Defenses](https://attack.mitre.org/techniques/T1562) | Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.  Adversaries may also impair routine operations that contribute to defensive hygiene, such as blocking users from logging out, preventing a system from shutting down, or disabling or modifying the update process. Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components. These restrictions can further enable malicious operations as well as the continued propagation of incidents.(Citation: Google Cloud Mandiant UNC3886 2024)(Citation: Emotet shutdown) |
| `T1027.012` | [Obfuscated Files or Information: LNK Icon Smuggling](https://attack.mitre.org/techniques/T1027/012) | Adversaries may smuggle commands to download malicious payloads past content filters by hiding them within otherwise seemingly benign windows shortcut files. Windows shortcut files (.LNK) include many metadata fields, including an icon location field (also known as the `IconEnvironmentDataBlock`) designed to specify the path to an icon file that is to be displayed for the LNK file within a host directory.   Adversaries may abuse this LNK metadata to download malicious payloads. For example, adversaries have been observed using LNK files as phishing payloads to deliver malware. Once invoked (e.g., [Malicious File](https://attack.mitre.org/techniques/T1204/002)), payloads referenced via external URLs within the LNK icon location field may be downloaded. These files may also then be invoked by [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)/[System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218) arguments within the target path field of the LNK.(Citation: Unprotect Shortcut)(Citation: Booby Trap Shortcut 2017)  LNK Icon Smuggling may also be utilized post compromise, such as malicious scripts executing an LNK on an infected host to download additional malicious payloads. |
