# Scheduled task created on remote endpoint

## Metadata

- **UUID**: `d11bfb38-3a0c-4e38-a973-efa2da1e8a73`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries with access to the right credentials can create scheduled tasks 
remotely from an endpoint they control for malicious purposes, which often 
include outbound connections to attacker infrastructure, binary execution, 
achieve persistance or registry entry editing or creation, but in this case
the remote scheduled task achieves lateral movement. 

Adversaries can create and configure scheduled tasks on remote endpoints 
using either the task scheduler or PowerShell.

One example syntax used to create a new task on a remote computer is to 
use \computername

Examples: 

at \\computername time/interactive | /every: date, ... /next: date, ... command
at \\computername id/delete | /delete /yes

Run a scheduled task on a remote mashine using PowerShell, example:

schtasks /run /s ComputerName /tn “description”

Using the task Scheduler, as example: > "Connect to Another Computer", 
provide the IP address of the remote system and select "Connect as another 
user" > "Set User".

## Techniques
- T1053
- T1053.005
