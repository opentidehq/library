# Pass the hash using impersonation within an existing process

## Metadata

- **UUID**: `479a8b31-5f7e-4fd6-94ca-a5556315e1b8`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries may use a particular flavor of pass the hash - to leverage 
an acquired handle (hash) on NT AUTHORITY\SYSTEM access token to spawn a 
new NT AUTHORITY\SYSTEM context process, impersonate the token for this
process into the attacker-desired existing thread, and then kill the 
spawned NT AUTHORITY\SYSTEM process again, making it a temp process used
to allow the threat actor to elevate privileges to NT AUTHORITY\SYSTEM.

This sets the technique apart from spawning a new process with the 
attacker-desired privileges that pass the hash without use of the 
/IMPERSONATE option leads to. 

Elevating privileges on Windows to System allows a threat actor (or 
sysadmin) to do things that are not possible without SYSTEM/root 
privileges.

Pass the hash is a method of authenticating as a user without having 
access to the user's cleartext password by stealing password hashes. This 
method bypasses standard authentication steps that require a cleartext 
password, moving directly into the portion of the authentication that uses 
the password hash. 

Mimikatz sekurlsa module with the /impersonate option implements this
particular approach as an option alongside other more known NTLM based
procedures.

## Techniques
- T1550.002
