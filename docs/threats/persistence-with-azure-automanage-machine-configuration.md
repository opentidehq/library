# Persistence with Azure Automanage Machine Configuration

## Metadata

- **UUID**: `23f6a192-a25d-48b8-a235-7bb55e483682`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Azure Policy enables administrators to define, enforce and remediate
configuration standards on Azure resources and even on non Azure assets
using Azure Arc. One key feature, that was released in 2021, is the
guest configuration feature of Azure Policy. Azure Policy Guest 
Configuration is now called Azure Automanage Machine Configuration. 

Adversaries may use this functionality to gain persistence in an Azure 
environment if they have gained the necessary permissions within the 
subscription. And since Azure VMs are in many cases directly integrated 
in the on-Premises Active Directory it is possible to gain additional 
access there.

## Techniques
- T1484.001
