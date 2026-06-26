# NTLM credentials dumping via SMB connection

## Metadata

- **UUID**: `02311e3e-b7b8-4369-9e1e-74c0a844ae0f`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
### Attack vector related to Outlook vulnerability CVE-2023-23397

**key point: no user interaction**  

An attacker sends an email message with an extended MAPI property with a 
UNC path pointing to an SMB network share on a threat actor-controlled 
server.  

When a vulnerable Microsoft Outlook client (CVE-2023-23397) 
receives in the inbox, it processes that email.  

Without any user interaction, a connection to the remote SMB server is 
established and the user's NTLM negotiation message are passed in the 
hearders.  

The attacker can capture this message tp replay for authentication 
against other systems that support NTLM authentication.  

The attacker may also try to crack the original password if not too 
complex.  

The outbound NTLM negotiation message is passed with SMB and WebDav 
protocols (see Didier Steven's blog).

### Attack vector using a link a user will be enticed to click on

**key point: the user needs to click on the link**  

This attack is a subset of attackers objectives when using spear 
phishing emails with a link in message body or in an attachment.

#### Attack vector using Outlook vulnerability

A vulnerability like CVE-2024-21413, also known as the MonikerLink bug, 
allows remote code execution and the leakage of local NTLM information.  

Moniker-based links exploit a logic flaw in how vulnerable versions
of Outlook process certain file types, causing files to open in
editing mode instead of the sandboxed `Protected View`.  

If the malicious link points to SMB shares controlled by the attacker,
Windows automatically attempts to authenticate using NTLM credentials
enabling threat actors to steal NTLMv2 hashes for initial access.

## Techniques
- T1187
- T1190
- T1068
- T1212
