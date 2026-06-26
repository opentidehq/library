# access to management plane of security, network, or endpoint management appliances

## Metadata

- **UUID**: `63ab0120-28bc-4081-8184-c45d68b144b2`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
### overall description
Cyber espionage threat actors continue to target technologies that do not 
support endpoint detection and response (EDR) solutions such as firewalls, 
IoT devices, hypervisors, VPN technologies (e.g. Fortinet, SonicWall, 
Pulse Secure, and others) or endpoint management solutions like 
Endpoint Manager Mobile (EPMM).  

Those targets are often delivered as appliances (bundle of hardware and 
software) and most of the time they do not have full-fleshed OS features 
and come with limited command line interfaces.  

Best practice is to have out-of-band (OoB) management from a central 
management console (dedicated network segment).  

Network seggregation, identity and access management for this OoB segment 
has to be strictly configured and monitoring in place to detect any unusual
source, account or actions performed.  

This can be a challenging objective as it depends on the level of verbosity
of aufit logs (if any).  

If configuration is loose or management access is inadvertly allowed 
from other interfaces, attackers may use valid accounts to access the 
management plane of the device.  

Moreover those devices are most of the time by definition inline of 
network flows coming from Internet. Attacker may obtain a Zero-day 
vulnerability resulting in access to command line interface of the 
device from the Internet-facing interfaces or privileged access 
(adminitrator).

### examples of specific attacks
#### attack against Fortinet Fortigate firewall
The attack against Fortigate is an illustration of the latter.  
The following appliances have been in scope:
  - FortiGate: FortiGate units are network firewall devices which allow 
  for the control and monitoring of network traffic passing through the
  devices.
  - FortiManager: The FortiManager acts as a centralized management
  platform for managing Fortinet devices.
  - FortiAnalyzer: The FortiAnalyzer acts as a centralized log management 
  solution for Fortinet devices as well as a reporting platform.

The following steps generally describe the actions the threat actor took:
  - Utilized a directory traversal zero-day (CVE-2022-41328) exploit to 
  write files to FortiGate firewall disks outside of the normal bounds 
  allowed with shell access.
  - Maintained persistent access with Super Administrator privileges within
   FortiGate Firewalls through ICMP port knocking 
  - Circumvented firewall rules active on FortiManager devices with a 
  passive traffic redirection utility, enabling continued connections to 
  persistent backdoors with Super Administrator privileges
  - Established persistence on FortiManager and FortiAnalyzer devices 
  through a custom API endpoint created within the device
  - Disabled OpenSSL 1.1.0 digital signature verification of system files
   through targeted corruption of boot files 

#### attack against Ivanti Endpoint Manager Mobile (EPMM) 
"An authentication bypass vulnerability in Ivanti EPMM allows unauthorized 
users to access restricted functionality or resources of the application 
without proper authentication,"  

A "trusted source" informed Ivanti that CVE-2023-35078 was exploited in 
attacks against a limited number of customers.

## Techniques
- T1027
- T1068
- T1070
- T1070.003
- T1070.004
- T1078
- T1140
- T1202
- T1222
- T1497
- T1497.001
