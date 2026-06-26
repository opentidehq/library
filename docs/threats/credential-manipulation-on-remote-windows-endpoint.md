# Credential manipulation on remote Windows endpoint

## Metadata

- **UUID**: `cfc6369a-e3df-4827-bb0d-969342f1558c`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors can perform credential manipulation on a remote Windows
endpoint with a variety of tools like: Mimikatz, WMIExec, WinRM-based,
PsExec, SMBExec or PowerShell or others to extract credentials from
a credential storage point on the endpoint, as example from the endpoint's
memory. This can be done by an attacker who already has gained access to
and control of one endpoint.

Requirements:

- permissions to access the remote machine
- permission/ability to run credential dumping tools
- or an ability to start a service remotely

Impacket PsExec example with username and password:

python3 psexec.py <domain>/<user>:<pass>@<target_host>

or an option with NTLM hashes

python3 psexec.py -hashes <lmhash>:<ntlmhash> <domain>/<user>@<target_host>

Example for Impacket SMBExec with plaintext credentials and NTLM hashes:

python3 smbexec.py "<domain>/<user>:<password>"@<target_host>

python3 smbexec.py -hashes <lmhash>:<ntlmhash> <domain>/<user>@<target_host>

Impacket suite contains a python script and can read the content of the
registry keys and decrypt the LSA Secrets passwords.

Example:

impacket-secretdump -sam /root/Desktop/sam.save -security /root/Desktop/security.save -system /root/Desktop/system.save LOCAL

## Techniques
- T1098.001
- T1003
