# Move laterally with SMB by abusing WMI

## Metadata

- **UUID**: `f33a693b-04cd-476e-9067-9deab561e55a`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Windows management instrumentation (WMI) is a tool that is implemented as service to locally
and remotely manages data, operations and configuring settings on windows operating systems.
WMI allows the administrator to see how the Operating system operates, what are its configurations
and properties and to automatically collect a systems hardware and software data. It is supporting other
scripting languages like Windows Script Host, VBScript, and PowerShell. WMI can be interacted
locally and remotely. WMI is a powerful tool which allows the threat actor to install backdoor, 
code execution as well as do lateral movement.
As the threat actor has the valid credentials (password or hashes) they can specify malicious events to
happen for example every time the victim restarts the computer run the executable that is present
in the specified directory.

Payload loaded may allow the threat actor to make a separate call to the Remote Procedure Call (RPC) 
on the victim machine, which is running over the SMB protocol.
The named pipe is then used to move laterally with the protocol.

## Techniques
- T1570
- T1047
