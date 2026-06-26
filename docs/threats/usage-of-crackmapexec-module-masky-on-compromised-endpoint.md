# Usage of CrackMapExec module Masky on compromised endpoint

## Metadata

- **UUID**: `9d4658ad-d4d5-4f3c-990f-bb486edd47f4`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
CrackMapExec is a post-compromise tool that contains a number of
modules and functionalities that allow red teams, pentesters and
threat actors to perform post-compromise actions. Detecting
both the presence of the tool itself, plus the usage of the tool
is an important baseline security detection.

Masky is a python library providing an alternative way to remotely
dump domain users’ credentials thanks to an ADCS. A 
command line tool has been built on top of this library in order to
easily harvest PFX, NT hashes and TGT on a larger 
scope.

This tool does not exploit any new vulnerability and does not work by
dumping the LSASS process memory. Indeed, it 
only takes advantage of legitimate Windows and Active Directory features
(token impersonation, certificate 
authentication via kerberos and NT hashes retrieval via PKINIT).

Masky is a new module, which in certain ways is less noisy than
dumping LSASS, but if AD CS CAs have auditing enabled, will be
very noisy and detectable.

## Techniques
- T1003
