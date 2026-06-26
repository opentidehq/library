# Passing SeDebugPrivilege to AdjustTokenPrivilege API elevating privileges of a running process

## Metadata

- **UUID**: `5d373113-18f9-41bb-bdde-3abbfa53cb86`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor can attempt to escalate privileges from a user or 
administrator context to NT SYSTEM by using the SeDebugPrivilege to adjust 
the memory of running process with a call to the AdjustTokenPrivilege API. 
This method uses built-in Windows APIs and commands to escalate privileges 
by changing the privileges of the running process in-memory. See Palantir 
reference. 

The intention of access token impersonation/theft is to grant a process the 
same permissions as another running process with a specific context, often 
NT SYSTEM. This may increase the capabilities of the now-elevated process 
or reduce its probability of detection.

For access token impersonation an adversary can use standard command-line 
shell to initiate 'runas' commands or to use payloads that call Windows 
token APIs directly. The changes in Windows API calls can manipulate 
access tokens for further account access and malicious purposes.

## Techniques
- T1134.001
