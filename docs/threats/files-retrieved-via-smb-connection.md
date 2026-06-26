# Files retrieved via SMB connection

## Metadata

- **UUID**: `f79a55a2-95bf-446d-a667-1bcf00f1b9f1`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
### The SMB Protocol
SMB stands for Server Message Block. It is a network protocol used to 
share data between computers and devices on a local or wide area network. 
The protocol allows local network computers to interact with file shares.

Threat actors frequently exploit SMB for their nefarious activities. 
One common tactic involves leveraging SMB to interact with file shares, including Microsoft Sharepoints, OneDrive or some NAS servers. 
In doing so, adversaries can pull malicious files from compromised endpoints, 
paving the way for the execution of additional malicious code. 
This method poses a significant threat, as it allows for the clandestine transfer of harmful files between systems, 
thereby supporting lateral movement within the network. 
Threat actors may exploit inherent file sharing protocols like SMB/Windows Admin Shares, 
either to connected network shares or through authenticated connections via Remote Desktop Protocol.

Moreover, the embedding of files can serve as a vector for initiating SMB connections. 
For instance, embedded files containing links executed by Office applications may establish 
connections with SMB servers under the threat actor's control. This technique allows threat actors to exploit unsuspecting users, 
initiating SMB connections that may lead to the execution of malicious code.

In a more advanced scenario, threat actors might specify a malicious server, 
directing the SMB protocol to facilitate further code execution. 
This strategic move enables them to retrieve various types of files, potentially leading to widespread infection across entire machines within the network. 
The ability to specify a malicious server amplifies the threat, 
as it allows threat actors to exercise greater control over the execution and distribution of harmful payloads, posing a severe risk to the overall security of the network.

## Techniques
- T1570
- T1021.002
- T1021.007
