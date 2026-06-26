# WhisperGate wiper

## Metadata

- **UUID**: `68ab86f6-378d-4371-ad01-6209fb95d57d`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
WisperGate is a multi-stage malicious wiper disguised as ransomware,
firstly considered as ransomware but later investigations and analysis
show that it's not only disabling the work of the impacted device
but deletes/corrupts the whole hard drive and destroys the data stored
on it by wiping the master boot record. ref [1]

This is very impactful and severe type of a malware because the system
needs the MBR (the Master Boot Record) to start the operation system
during the boot.   

For the first time this type of a wiper was observed in the beginning
of the conflict between Russia and Ukraine in Feb 2022. Later the
reports published new activities of WisperGate as part of a more
broader campaign that aimed to coordinate destructive cyberattacks
against critical infrastructure and other targets in a combination
with kinetic military operations (active physical operations on
place).

The GRU's WhisperGate campaign targets government and military
institutions and the goal is to achieve as much as possible
disruption of the systems and a total lost of any stored
information on them.   

Different research investigations showed that initally it was
likely that stolen credentials provided the access point for
the deployment of the wiper. Other known for this wiper at this
moment is that it contains two types of wipers.   

1. The first wiper attempts to destroy the master boot record (MBR) and
to eradicate any recovery options. Similar to the notorious NotPetya wiper
that masqueraded as ransomware, WhisperGate is not intended to be an actual
ransom attempt, since the MBR is completely overwritten. ref [2]      

2. In the second stage, a downloader pulls the code required for
the third step. After a base64-encoded PowerShell command is executed
twice and an endpoint is requested to enter sleep mode for 20 seconds.
A Discord server URL, hardcoded into the downloader, is then pinged
to grab a .DLL file. ref [2]  

In the further stage of the attack process DLL loader is trying
to gain administrative privileges. For example, it will attempt
to escalate itself by trigger User Account Control (UAC) dialog box.
Once granted Administrator privileges it drops VBScript from a Temp
directory. The script adds the targeted logical drive to the Windows
Defenders list of exclusions, using PowerShell commands ref [5].    

The script contains encoded assembly parts. For decoding of this function,
a threat actor uses obfuscation Eazfuscator tool. It can use a combination
of RC4 and XOR loop to decode the content off the base64 string.  

The script uses another PowerShell commands further to stop the function
of Windows Defender and uses a second command with "rmdir" to recursively
delete all Windows Defender files.

The threat actors developed WhisperGate implemented their own cryptographic
functions that are built on top of standard and proven libraries. They
attempted to wipe files in a strange and seemingly slap-dash manner,
which may or may not have been intentional. ref [5]  

In Ukraine, a pro-Russian group was detected to conduct destructive attacks
such as the WhisperGate wiper attacks against ICS targets.

## Techniques
- T1485
- T1561.001
- T1561.002
- T1562.001
- T1036
- T1134.002
