# Abuse of environment variable to hijack library functions

## Metadata

- **UUID**: `4d0bd987-1430-4433-9b58-a71ba8798435`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
This threat vector focuses on the malicious use of the `LD_PRELOAD` environment 
variable on Linux systems to hook or hijack library function calls. Attackers, 
Red Teams, and advanced persistent threats leverage this trick to intercept and 
modify the behavior of dynamically linked libraries before the legitimate 
functions are called. By loading a rogue or malicious library via `LD_PRELOAD`, 
adversaries can achieve elevated privileges, persist on the target, and run 
arbitrary code under the guise of otherwise legitimate processes.    

Scenario example: 
- An attacker already possessing local or remote administrative access to a Linux 
host can set or modify the `LD_PRELOAD` environment variable in order to inject 
custom libraries during program execution.   

- When an application starts, the system dynamic linker reads the `LD_PRELOAD` variable 
and forces the loading of the malicious library.  

- The malicious library intercepts and potentially manipulates function calls—such as 
file I/O or network operations—allowing attackers to subvert security controls or 
execute code of their choice.

```bash
LD_PRELOAD=/tmp/malicious.so /usr/bin/anyApp
```

This indicates that a potentially unauthorized library (`/tmp/malicious.so`) is being 
force-loaded into `anyApp`.

## Techniques
- T1574.006
