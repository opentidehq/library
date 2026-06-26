# Create a process with a token

## Metadata

- **UUID**: `54adba8e-e3f8-43e2-bcd5-7c3cd61112d9`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries may create a new process with a different token 
to escalate privileges and bypass access controls. A processes 
can be created with the token and resulting security context 
of another user using features such as CreateProcessWithTokenW 
and runas.

An adversary creates a new access token with DuplicateToken(Ex) 
and uses it with CreateProcessWithTokenW to create a new process 
running under the security context of the impersonated user. 
This is useful for creating a new process under the security 
context of a different user.

## Techniques
- T1134.002
