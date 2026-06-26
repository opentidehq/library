# Abuse of Getsystem command for privilege escalation

## Metadata

- **UUID**: `49625e57-94e0-4185-8466-ac68fe15b7e1`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Use of Getsystem command to elevate from a local administrator to the SYSTEM user.
There are different tools to do this, most popular are Cobalt Strike beacons and 
Metasploit Meterpreter payload.

Both tools first attempt to use “named pipe impersonation” to achieve SYSTEM privileges.
This involves creating a Windows Service to execute as NT AUTHORITY\SYSTEM and feeding
data to it through a named pipe that is randomly created by the malicious payload.

The getsystem command has three techniques. The first two rely on named pipe impersonation.
The last one relies on token duplication.

## Technique 1.

It creates a named pipe from Meterpreter. It also creates and runs a service that runs
cmd.exe /c echo “some data” >\\.\pipe\[random pipe here]. When the spawned cmd.exe connects
to Meterpreter’s named pipe, Meterpreter has the opportunity to impersonate that security 
context. Impersonation of clients is a named pipes feature. 
The context of the service is SYSTEM, so when you impersonate it, you become SYSTEM.

## Technique 2.

It is like technique 1. It creates a named pipe and impersonates the security context of
the first client to connect to it. To create a client with the SYSTEM user context,
this technique drops a DLL to disk(and schedules rundll32.exe as a service to run the
DLL as SYSTEM. The DLL connects to the named pipe.

## Technique 3.

It is a little different. This technique assumes you have SeDebugPrivileges—something getprivs
can help with. It loops through all open services to find one that is running as SYSTEM and
that you have permissions to inject into. It uses reflective DLL injection to run its elevator.dll
in the memory space of the service it finds. This technique also passes the current thread id 
(from Meterpreter) to elevator.dll. When run, elevator.dll gets the SYSTEM token, opens the primary 
thread in Meterpreter, and tries to apply the SYSTEM token to it.

This technique’s implementation limits itself to x86 environments only. On the bright side, 
it does not require spawning a new process and it takes place entirely in memory.

## Techniques
- T1134.002
