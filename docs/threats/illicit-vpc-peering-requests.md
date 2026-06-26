# Illicit VPC peering requests

## Metadata

- **UUID**: `cf14af27-ea36-4306-9134-8d9ccb69a617`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors may attempt to gain initial access to EC AWS environments by
sending a malicious/illicit VPC peering request to EC VPC administrators.
If the VPC administrator approves the request, the adversary would see their 
network joined with the target, and be able to pivot there freely.

VPC peering requests could also be used in the data exfil stage by 
a threat actor using this method to send data out of an EC AWS account
that the threat actor controls

Virtual Private Clouds, or VPCs, is a logically isolated portion of 
networking that AWS assigns to clients. VPC peering is a feature that allows VPCs
living in different accounts to be joined in a common IP space, for example to 
allow different services to communicate to each others.

## Techniques
- T1078.004
- T1599
