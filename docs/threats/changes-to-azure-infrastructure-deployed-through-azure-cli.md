# Changes to Azure infrastructure deployed through Azure CLI

## Metadata

- **UUID**: `60c5b065-7d06-4697-850f-c2f80765f10b`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor in control of the prerequisites may attempt to use the Azure
CLI to perform changes either to the endpoint from which the CLI is 
accessed or on remote infrastructure, user accounts, service principals, 
or configurations. 

A threat actor can only perform changes that are allowed in the scopes of
credentials, temporary credentials, or service principals that the threat 
actor has control of, barring usage of a vulnerability in Azure to allow
more than that.

## Techniques
- T1059
