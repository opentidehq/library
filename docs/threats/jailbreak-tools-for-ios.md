# Jailbreak Tools for iOS

## Metadata

- **UUID**: `024a10fb-fc65-485b-9d7c-98a2372d75c0`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-04-09`
- **Modified**: `2025-04-16`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://idevicecentral.com/jailbreak-tools/ios-jailbreak-tools/](https://idevicecentral.com/jailbreak-tools/ios-jailbreak-tools/)
- **2**: [https://github.com/iOS17/Jailbreak](https://github.com/iOS17/Jailbreak)

## Description
Jailbreaking an iPhone involves bypassing Apple's security restrictions to gain 
root access to the device, allowing users to install unauthorized apps, tweaks, 
and customizations. While this can provide enhanced functionality, it also introduces 
significant security risks. Below is an analysis of the threat vector associated 
with jailbreaking tools based on the provided sources.

### Jailbreaking Tools

Jailbreaking tools exploit vulnerabilities in iOS to remove Apple's restrictions. 
These tools vary depending on the iOS version and device type. For example:
- **Taurine** works for iOS 14.0–14.8.1.
- **Dopamine 2.x** supports iOS 15.0–16.6.1 on certain devices.
- **PaleRa1n** is used for older devices (A11 and below) running iOS 15–17.

These tools often leverage kernel vulnerabilities to enable capabilities such as 
tweak injection, theming, and sideloading apps.

### Types of jailbreaks:

1. Tethered jailbreak: Requires the device to be connected to a computer to boot into
    a jailbroken state.

2. Semi-tethered jailbreak: Allows the device to boot into a jailbroken state without
   being connected to a computer, but may require a computer to re-jailbreak the device
   after a reboot.

3. Untethered jailbreak: Allows the device to boot into a jailbroken state without being
   connected to a computer, and the jailbreak is preserved even after a reboot.

### Security Risks of Jailbreaking

1. **Exploitation of Vulnerabilities**:
  - Jailbreaking tools exploit known vulnerabilities in iOS, which inherently weakens 
  the device's security posture. Once jailbroken, the device becomes more susceptible 
  to malware and unauthorized access.

2. **Loss of System Integrity**:
  - Jailbreaking modifies the core system files, potentially leading to instability, 
  crashes, or bricking of the device.

3. **Exposure to Malicious Software**:
  - Many jailbreak tweaks and apps are distributed outside of Apple's App Store, 
  increasing the risk of installing malicious software.

4. **Bypassing Security Features**:
  - Features like Secure Enclave and sandboxing are compromised in a jailbroken 
  environment, exposing sensitive data such as passwords and encryption keys.

5. **No Official Support**:
  - Apple does not support jailbroken devices, leaving users without official updates 
  or security patches.

### Current Status of Jailbreak Tools
- For newer iOS versions (iOS 17 and 18), no full jailbreak tools are publicly available 
yet. However, semi-jailbreak solutions like MisakaX and Nugget exist for limited customization.
- Older versions (iOS 15 to 16) have stable jailbreaks like Dopamine and PaleRa1n with 
tweak support.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **If adversaries have physical access to the device, they can install a jailbreaking tool
that include the neccesary exploit. If no physical access is available, it is possible
to exploit a zero-day vuln to bypass the device' security mechanisms.

Domains: Mobile
Targets: Mobile phone, Personal Information, Tablet
Platforms: iOS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Identity Theft; Impairement; IP Loss; Lose Capabilities | - |
| Leverage | Spoofing; Tampering; Information Disclosure; Software installation | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1630.003` | [Mobile : Disguise Root/Jailbreak Indicators](https://attack.mitre.org/techniques/T1630/003) | An adversary could use knowledge of the techniques used by security software to evade detection.(Citation: Brodie)(Citation: Tan) For example, some mobile security products perform compromised device detection by searching for particular artifacts such as an installed "su" binary, but that check could be evaded by naming the binary something else. Similarly, polymorphic code techniques could be used to evade signature-based detection.(Citation: Rastogi) |
| `T1398` | [Mobile : Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1398) | Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts are part of the underlying operating system and are not accessible to the user unless the device has been rooted or jailbroken. |
