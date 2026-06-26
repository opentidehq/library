# Tampering system firewall on endpoint

## Metadata

- **UUID**: `be73532a-1994-4db2-945e-ccdf586e2551`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
The firewall is a foundational defensive mechanism designed to control inbound and 
outbound network traffic based on predefined security rules. By disabling 
or tampering with these rules, adversaries effectively remove a key layer of network 
segmentation and monitoring. This action can allow them to pivot laterally, exfiltrate 
data without triggering alerts, or execute follow-on attacks with minimal interference 
from host-based defenses.  

## Windows 

An attacker with administrative privileges may execute commands such as 
`netsh advfirewall set allprofiles state off` or directly manipulate registry keys :
(`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`) 
to turn off or weaken firewall profiles. 
They may also employ PowerShell scripts or WMI-based methods to silently adjust rules.  

## Linux 

Threat actors might run commands like :
`iptables -F` (flush all rules), `iptables -P INPUT ACCEPT`, 
or tamper with `/etc/iptables.rules` files to ensure that all traffic is allowed. 

On some distributions, adjusting systemd firewall services or security daemons 
can achieve the same effect.  

## macOS

Attackers could use the `pfctl` command (e.g., `sudo pfctl -d`) to disable the 
Packet Filter firewall, or modify system configuration files that govern firewall rules. 
They may also exploit launch daemons or kernel extensions to bypass 
or remove firewall protections.

## Techniques
- T1562.004
