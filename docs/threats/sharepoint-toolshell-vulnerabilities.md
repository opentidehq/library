# SharePoint ToolShell vulnerabilities

## Metadata

- **UUID**: `55227203-38dc-406b-943a-9c1c6023d1cd`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
SharePoint zero-day vulnerabilities, known also as `ToolShell` are affecting
on-premise Microsoft SharePoint servers, which enable the attackers to
execute code on SharePoint servers without authentication, bypassing
security mechanisms. This vulnerabilities are considered with a high
security risk because they may lead to a remote code execution (RCE)
and a fully compromise of a SharePoint environment. 

What is known until now for these vulnerabilities is that a threat actor
deploys initially a malicious ASPX file `spinstall0.aspx`, also knows as
`SharpyShell`. The malicious file purpose is to extract and leak
cryptographic secrets from the SharePoint server using a simple GET request.
The goal of the threat actor is to obtain the server's MachineKey
configuration, including the critical ValidationKey , which are essential
for generating valid payloads ref [1].    

With these keys, the attackers can effectively turn any authenticated
SharePoint request into a remote code execution opportunity, bypassing the
need for credentials and gaining full control of the server.  

The attacker then uses a tool called `ysoserial` to craft their own valid
SharePoint token for remote code execution with full persistence and no
authentication ref [2].

It was identified successful zero-day exploitation in the SharePoint systems
of at least seven Union entities. But those incidents were not considered
as severe incident because the Defender EDR blocked post-compromise attempts.
Based on the current analysis and investigation there was not detected any
leak of credentials used for post-exploitation activities.

At this moment Microsoft released new SharePoint patches to fix these
vulnerabilities. Microsoft has released security updates that fully protect
customers using all supported versions of SharePoint affected by these two
vulnerabilities. For more information about patching review the customer
guidance for SharePoint vulnerability ref [3],[4].

## Techniques
- T1190
- T1212
- T1078
