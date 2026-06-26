# Adversary abuses sudo elevation control mechanism

## Metadata

- **UUID**: `422098a7-567e-47fe-9e92-9fd3ec6df768`
- **Schema**: `threat::1.0`
- **Version**: `3`
- **Created**: `2022-10-27`
- **Modified**: `2022-12-21`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://steflan-security.com/linux-privilege-escalation-sudo-commands-binaries/](https://steflan-security.com/linux-privilege-escalation-sudo-commands-binaries/)
- **2**: [https://gtfobins.github.io/](https://gtfobins.github.io/)
- **3**: [https://gtfobins.github.io/gtfobins/tar/](https://gtfobins.github.io/gtfobins/tar/)
- **4**: [https://gtfobins.github.io/gtfobins/pkexec/](https://gtfobins.github.io/gtfobins/pkexec/)

## Description
Sudo is a command-line utility for Unix and Linux-based systems that can
provide an effective way to give specific user permissions to run root
(most powerful) level commands on the system. Unfortunately, some
misconfigurations in sudo functionality can allow threat actors to escalate
their privileges to root access.

If the file /etc/sudoers (used to store all sudo privileges) is modified
this can grant to the attacker elevation of privileges. Attackers may use
custom parameters with sudo to edit the sudoers file. For example -f or -l
can be used to edit this file or list which commands or binaries the
current user has access to run.

GTFOBins is a list of Unix binaries which is used by the threat actors to
bypass local security restrictions in misconfigured systems. GTFOBins
allows to search for binaries or commands whether they are executed as sudo
and if they provide access to normally restricted actions. The repo list
contains 300+ commands that could be abused for different purposes if not
configured using this filter. The current list is an open collaborative
project. Link: https://gtfobins.github.io/#+sudo

Examples: 

A "tar" option can be exploited to write to arbitrary files (works only for
GNU tar). If write data to files, it may be used for privileged writes on
the files ouside a restricted file system. A "tar" command can break out
from restricted environments, using spawn of an interactive system shell.

Reference: https://gtfobins.github.io/gtfobins/tar/

tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

For GNU tar:
tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'

or (for GNU tar when limited command argument injection is available)

TF=$(mktemp)
echo '/bin/sh 0<&1' > "$TF"
tar cf "$TF.tar" "$TF"
tar xf "$TF.tar" --to-command sh
rm "$TF"*

The pkexec command can be exploited to gain a root shell and to access the
file system, escalate or maintain privilege access. 

Reference: https://gtfobins.github.io/gtfobins/pkexec/

sudo pkexec /bin/sh

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actor needs root level access to edit the sudoers file.

Domains: Enterprise
Targets: Control Server, Remote access
Platforms: Linux**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Business disruption; Data Breach; Identity Theft; Impairement | - |
| Leverage | Elevation of privilege; Dwelling; Infrastructure Compromise | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1548` | [Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548) | Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk.(Citation: TechNet How UAC Works)(Citation: sudo man page 2018) An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.(Citation: OSX Keydnap malware)(Citation: Fortinet Fareit) |
