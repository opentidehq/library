# Grager backdoor

## Metadata

- **UUID**: `662af2da-7017-4899-88fc-e77617a15130`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A previously unseen backdoor named Grager was deployed against three
organizations in the past - Taiwan, Hong Kong, and Vietnam in April
2024. Trojan.Grager is a second APT malware implant leveraging the
Microsoft Graph API from a multi-step malware campaign abusing
cloud services ref [1, 2].  

The analysis of the backdoor revealed that it used the Graph
API to communicate with a C&C server hosted on Microsoft OneDrive.
Grager was downloaded from a typosquatted URL mimicking an open-
source file archiver 7-Zip (7 zip .msi file) ref [1].  

The .msi dropper, is a Trojanized 7-Zip installer that installs
the real 7-Zip software into the Windows Program Files folder
(C:\Program Files (x86)\7-Zip) along with a malicious DLL named
`epdevmgr.dll`, a copy of the Tonerjam malware, and the encrypted
Grager backdoor into a file named `data.dat` ref [1].   

The backdoor leverages a custom application layer protocol for
communication with its command and control server, allowing it to bypass
traditional network security tools and evade detection. Grager employs
various stealth techniques, such as obfuscation and anti-analysis methods,
to evade antivirus software and remain undetected.

## Techniques
- T1071
- T1105
- T1059
