# Spearphishing with an attachment extension .rdp

## Metadata

- **UUID**: `58b98d75-fc63-4662-8908-a2a7f4200902`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Spearphishing with an attachment extension .rdp refers to a targeted
cyberattack where a malicious actor sends an email containing a file
with the file extension .RDP (Remote Desktop Protocol) to a specific
individual or organization. The attacker may send an attachment to
the end-users directly or by impersonating companies, institutions
or particular individuals, sending the lure on behalf of them
ref [1, 2].       

On October 22, 2024, the National Cyber Security Centers (NCSC) of two
EU countries, as well as governmental organizations [3] reported that
a spear-phishing campaign with .RDP attachment are impersonating their
entities.      

The emails were highly targeted, using social engineering lures relating
to Microsoft, Amazon Web Services (AWS), and the concept of Zero Trust.
The emails contained a Remote Desktop Protocol (RDP) configuration file
signed with a LetsEncrypt certificate. RDP configuration (.RDP) files
summarize automatic settings and resource mappings that are established
when a successful connection to an RDP server occurs ref [1].       

This allows the adversary to potentially deploy additional payloads,
execute local reconnaissance activities, and to redirect targeted users
to credential harvesting sites.

## Techniques
- T1566.001
- T1204.002
- T1036

## Chaining
```mermaid
flowchart LR
58b98d75_fc63_4662_8908_a2a7f4200902["Spearphishing with an attachment extension .rdp"]
dd5d942c_bac4_4000_b9a6_ca4fef6cfb84["Spearphishing Attachment"]
58b98d75_fc63_4662_8908_a2a7f4200902 --> dd5d942c_bac4_4000_b9a6_ca4fef6cfb84
```
