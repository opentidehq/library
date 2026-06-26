# DLL Execution over Rundll32

## Metadata

- **UUID**: `f3a392f7-3268-4c54-8bfa-8117b784f520`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Rundll32.exe is a powerful asset for adversaries to proxy execution of arbitrary
and malicious code. It is flexible and efficient for loading code into memory,
as may load malicious DLLs by ordinals, function names or directly.
Rundll32.exe has a certain degree of trust; which can result in a possible
AppLocker and Software Restriction Policies (SRP) bypass.

Adversaries rely on distinct vectors to infect their targets, who might get
infected. Upon successful exploitation, malicious actors have been seen executing
DLL files using Rundll32.exe for multiple purposes; such as download and execute a
payload from a remote server (DLL path could be both local and remote when the DLL
is hosted on a SMB share using UNC paths), contact C&C server to upload stolen data
or dump LSASS process memory to obtain credentials.

## Techniques
- T1218.011
