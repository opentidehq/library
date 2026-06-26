# AWS Compute instance deployed in unusual region

## Metadata

- **UUID**: `1040ebd2-4659-4844-9238-95fa69a7e63c`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Certain threat actors will try to launch AWS compute instances 
(EC2, EKS, ECS) instances to achieve their objectives

One of the main vectors currently is to monetize access to 
privileged AWS credentials by deploying new compute instances of various types 
to mine cryptocurrencies. To hide their deployed instances, a threat actor 
may deploying the resources into unused regions, where they may go 
unnoticed.

Additionally threat actor may launch compute instances to act as staging 
platforms for serving malware for other campaigns.

It is expected that threat actors will potentially use compute instances 
for other purposes than the 2 listed above.

## Techniques
- T1496
