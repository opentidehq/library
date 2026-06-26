# Scheduled tasks created with PowerShell

## Metadata

- **UUID**: `a5f631c3-6fb0-484f-89e4-c8b2e038db8f`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor can use PowerShell to create tasks for nefarious purposes. 

Scripts requires admin rights to create a new scheduled task. The script 
will run in the context of the user who created the scheduled task.

Scheduled tasks are typically used to either connect to adversary 
infrastructure, establish persistence or to execute binaries.

## Techniques
- T1053.005
