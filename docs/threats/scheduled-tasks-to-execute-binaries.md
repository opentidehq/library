# Scheduled tasks to execute binaries

## Metadata

- **UUID**: `707bf160-5d78-42cc-85d3-e4831f62357c`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor can use scheduled tasks to execute binaries such as LOLBINs
or malware. LOLBINs is short for 'living off the land binaries', which
means that the threat actors often use native Windows binaries to try to
hide malicious activity.

A scheduled task to execute a binary is a way for an attacker to ensure 
that binaries of their choosing and with their settings are run
automatically at a specific time or on a regular basis. Scheduled tasks can
be set up to run a malicious binaries or LOLBINs in a number of ways, such
as through the use of the built-in task scheduler in Windows. Once the
scheduled task is created, it will run the specified binary at the
designated time. It is important to regularly check and disable any
suspicious scheduled tasks to protect against this type of attack.

## Techniques
- T1053.005
