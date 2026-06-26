# Duplicate an access token in a new process to elevate privileges

## Metadata

- **UUID**: `349348ca-66f5-41d2-8610-6bb61556d773`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
An adversary can use automated solutions like CobaltStrike framework
to create a new process with a duplicated token to escalate privileges 
and bypass access controls. An adversary can duplicate a desired access 
token with DuplicateToken(Ex) and use it with CreateProcessWithTokenW 
to create a new process running under the security context of the 
impersonated user. This is useful for creating a new process under 
the security context of a different user.

The new process runs in the security context of the specified token. 
It can optionally load the user profile for the specified user.
Usually the function CreateProcessWithTokenW is running like 
a process winbase.h 

The process that calls CreateProcessWithTokenW must have 
SE_IMPERSONATE_NAME privilege. 

Adversaries commonly use token stealing to elevate their security context 
from the administrator level to the SYSTEM level. An adversary can use a 
token to authenticate to a remote system as the account for that token if the 
account has appropriate permissions on the remote system.

Example for spawn of a process with token duplication:
The process spawn is usually with PID (Process Identifier): 2572

spawn windows/beacon_https/reverse_https (<ip_address>:443) 
in a high integrity process (token duplication)

## Techniques
- T1134.002
