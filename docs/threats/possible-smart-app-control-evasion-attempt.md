# Possible Smart App Control Evasion Attempt

## Metadata

- **UUID**: `dcf021a5-2846-40b4-8189-2695a7a32b9a`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Smart App Control is a cloud-powered security feature in Windows 11 designed to 
block malicious, untrusted, and potentially unwanted applications from running. 
It uses a combination of reputation checks and digital signatures to determine whether 
an application is safe to execute. If an app is not recognized or is considered 
risky, SAC blocks its execution.

## Main Evasion Techniques

**1. Registry Manipulation**
Registry manipulation is a common method in broader Windows attack vectors for disabling 
or bypassing security features. Adversaries may attempt to:
- **Disable or modify SAC-related registry keys** to weaken or turn off the feature.
- **Tamper with security policy settings** stored in the registry to lower protection levels.
  
**2. Code-Signing and Certificate Abuse**
One of the most prevalent methods to bypass SAC is to sign malware with a legitimate 
code-signing certificate. Attackers increasingly use Extended Validation (EV) certificates, 
which require identity verification, by impersonating legitimate businesses to obtain 
them. This allows malware to appear trustworthy and slip past SAC’s checks.

**3. Reputation-Based Evasion**
- **Reputation Hijacking:** Attackers repurpose trusted applications (like script interpreters) 
to load and execute malicious code without triggering alerts.
- **Reputation Seeding:** Attackers use seemingly innocuous binaries to trigger 
malicious behavior after a certain time or event.
- **Reputation Tampering:** Attackers alter parts of legitimate binaries to inject 
shellcode without losing their good reputation.

**4. LNK Stomping**
Attackers exploit the way Windows handles shortcut (LNK) files. By crafting LNK 
files with non-standard target paths or structures, they can remove the "mark-of-the-web" 
(MotW) tag before security checks are performed, allowing malicious payloads to 
bypass SAC.

**5. Social Engineering**
Attackers trick users into overriding security warnings or disabling SAC by posing 
as legitimate sources or using persuasive tactics.

**6. Living-Off-The-Land Binaries (LOLBins)**
Attackers abuse signed Microsoft-supplied binaries (e.g., `mshta.exe`, 
`rundll32.exe`, `regsvr32.exe`) to proxy execution of malicious scripts 
and payloads, which Smart App Control might not block if the binary is 
considered trusted.

## Techniques
- T1112
- T1195
- T1204
