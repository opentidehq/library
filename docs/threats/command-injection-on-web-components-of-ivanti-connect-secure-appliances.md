# Command injection on web components of Ivanti Connect Secure appliances

## Metadata

- **UUID**: `4b1c47ee-f45a-4b89-98e7-e943bcd5dd19`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Attackers may manage to inject commands to an Ivanti Connect Secure 
appliance (that provide remote VPN access to corporate 
infrastructures) either with valid credentials for vulnerable 
authenticated endpoints or exploiting a vulnerability to bypass 
authentication.  

These vulnerabilities are identified as CVE-2024-21888 and 
CVE-2024-21893. CVE-2024-21893 have been exploited in the wild chained 
with CVE-2024-21887 and can lead to remote adversaries to execute 
arbitrary commands on targeted gateways.

In addition to the list of LOLbins see [3], following commands were 
used in the ICS attack is the following:
- aria2c
- at
- cat 
- check_ssl_cert
- crash
- crontab
- echo
- mount
- nohup
- pidstat
- sed
- split
- sysctl
- tcpdump
- wireshark
- tshark

## Techniques
- T1190

## Chaining
```mermaid
flowchart LR
4b1c47ee_f45a_4b89_98e7_e943bcd5dd19["Command injection on web components of Ivanti Connect Secure appliances"]
810057c6_cb84_41e4_add4_ae56b52c8ab7["authentication bypass on Ivanti Connect Secure appliances"]
4d6104e3_10d4_4a12_b081_d937df848891["Web Shell Attacks"]
4b1c47ee_f45a_4b89_98e7_e943bcd5dd19 --> 810057c6_cb84_41e4_add4_ae56b52c8ab7
810057c6_cb84_41e4_add4_ae56b52c8ab7 --> 4d6104e3_10d4_4a12_b081_d937df848891
```
