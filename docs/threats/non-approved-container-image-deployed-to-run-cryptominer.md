# Non-Approved container image deployed to run cryptominer

## Metadata

- **UUID**: `eca91e9a-616f-4439-ac03-5d0ecc2266df`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor can gain access to deployment workflows and pipelines and can then abuse acquired access to deploy images of their own choosing to deploy a cryptominer either directly via a malicious image, or by deploying a clean image first and then a cryptominer and C2 Infrastructure

## Techniques
- T1610
- T1525
- T1496
