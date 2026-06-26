# Mimikatz execution on compromised endpoint

## Metadata

- **UUID**: `7351e2ca-e198-427c-9cfa-202df36f6e2a`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Mimikatz is a very versatile tool that comes with a lot of 
options and capabilities. Detection of known Atomic IOCs of 
the mimikatz tool itself or the atomic IOCs of invoke-mimikatz 
powershell scripts, is very important, as it both signals a 
compromised endpoint, plus shows a noisy threat actor trying 
to EoP and move laterally.

## Techniques
- T1134.005
- T1098
- T1547.005
- T1555.003
- T1555.004
- T1003.001
- T1003.002
- T1003.004
- T1003.006
- T1207
- T1558.001
- T1558.002
- T1552.004
- T1550.002
- T1550.003
