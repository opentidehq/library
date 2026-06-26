# Malicious kernel module

## Metadata

- **UUID**: `83343a35-daa0-41a2-ae09-6876b3ef9c11`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries may attempt to modify Linux kernel parameters or load/unload kernel 
modules to alter system behavior, hide malicious activities, or install rootkits. 
By operating at the kernel level, attackers can gain persistent and stealthy 
control over a system, intercepting system calls, hiding processes, files, 
or network connections.  

For example, an attacker with root access might execute insmod malicious_module.ko 
to load a malicious kernel module that conceals their presence and activities. 
Kernel rootkits like Adore-ng or Suterusu are examples of tools used for such purposes. 
These rootkits can hide network connections, processes, and files, effectively 
masking the adversary's footprint on the system.

## Techniques
- T1547.006
- T1014
