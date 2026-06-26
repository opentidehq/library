# Linux kernel module injection from container

## Metadata

- **UUID**: `dcccd7e5-9d3f-4b36-853a-5cd18a7ef752`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Loadable Kernel Modules (LKM) can be used by adversaries to deliver 
sophisticated and hard to detect rootkits. Each event where kernel modules 
are loaded from a container should be investigated with the exeption of 
Security tools deployed in containers.

An injected kernel module is just code execution, and can in theory do 
more or less anything, but threat actors mostly use this for dwelling and 
for hiding their presence on a system.

## Techniques
- T1547.006
