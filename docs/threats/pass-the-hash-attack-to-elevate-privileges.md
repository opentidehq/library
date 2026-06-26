# Pass the hash attack to elevate privileges

## Metadata

- **UUID**: `4472e2b0-3dca-4d84-aab0-626fcba04fce`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Elevating privileges on Windows to System allows a threat actor (or 
sysadmin) to do things that are not possible without SYSTEM/root 
privileges.

Pass the hash is a method of authenticating as a user, without having 
access to the user's cleartext password, by stealing password hashes and 
using this password hash to authenticate directly to a resource via a 
third party non-Microsoft tool such as Mimikatz. This method bypasses 
standard authentication steps that require a cleartext password, moving
directly into the portion of the authentication that uses the password 
hash.

Mimikatz sekurlsa module without the /impersonate option implements the standard
pass-the-hash technique, which works by authenticating to a resource, by in the 
background spawning a new process in the context of the hash and attacker-
desired elements. For examples, see the reference to thehacker.recipes.

## Techniques
- T1550.002
