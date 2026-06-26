# Android attack using app running on emulator

## Metadata

- **UUID**: `4a4a7c81-ca98-4761-8f23-7ef6354e9d1c`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-04-10`
- **Modified**: `2025-04-14`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://fingerprint.com/blog/android-emulator-tamper-fraud-detection/](https://fingerprint.com/blog/android-emulator-tamper-fraud-detection/)
- **2**: [https://www.infosecinstitute.com/resources/general-security/mobile-emulator-farms-what-are-they-and-how-they-work/](https://www.infosecinstitute.com/resources/general-security/mobile-emulator-farms-what-are-they-and-how-they-work/)
- **3**: [https://doverunner.com/blogs/tips-for-protecting-apps-from-attacks-with-android-emulator-detection/](https://doverunner.com/blogs/tips-for-protecting-apps-from-attacks-with-android-emulator-detection/)
- **4**: [https://www.claranet.com/uk/blog/bypassing-hardened-android-applications/](https://www.claranet.com/uk/blog/bypassing-hardened-android-applications/)

## Description
The threat vector involves exploiting emulated environments to bypass security measures, 
automate malicious activities, and manipulate app behavior. Below are key aspects 
of this threat:

## How the Attack Works
1. **Exploitation of Emulators**:
  - Android emulators like NoxPlayer, BlueStacks, or custom emulator farms are 
  used by attackers to mimic legitimate devices and bypass app security mechanisms.
  - Emulators provide attackers with a controlled environment to test and refine 
  their techniques before deploying them at scale.

2. **Fraudulent Activities**:
  - **Spoofing Device Identifiers**: Attackers use emulators to replicate legitimate 
  device identifiers (e.g., IMEI, OS version) obtained through malware or phishing 
  attacks, making fraudulent transactions appear genuine.
  - **Automation**: Scripts and automation frameworks enable large-scale fraud, 
  such as creating fake accounts, performing unauthorized transactions, or bypassing 
  authentication systems.
  - **Data Manipulation**: Emulators allow attackers to intercept and modify app 
  data or API calls for malicious purposes.

3. **Advanced Techniques**:
  - **Runtime Hooks**: Tools like Frida are used to hook into app functions dynamically, 
  altering system properties (e.g., `ro.kernel.qemu`) to make the emulator appear 
  as a physical device.
  - **Customized Emulator Farms**: Organized groups deploy emulator farms with 
  dozens of emulators to cycle through spoofed devices rapidly, avoiding detection 
  and maximizing fraud efficiency.

## Common Attack Scenarios
- **Financial Fraud**: Emulator farms have been used to steal millions from banks 
by automating fraudulent transactions while evading detection systems.
- **API Abuse**: Attackers reverse-engineer apps running on emulators to exploit 
APIs for unauthorized access or data theft.
- **App Tampering**: Emulators facilitate code injection or reverse engineering 
to modify app functionality and compromise security features.

## Key Components Used in These Attacks
- Access to compromised credentials (usernames/passwords) and device identifiers.
- Custom scripts for network interception and API manipulation.
- Cycling of spoofed devices to evade detection and maintain operational stealth.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries require users to download emulators that have been
compromised or misconfigured and through these, they can carry
out malicious activities.

Domains: Mobile
Targets: Mobile phone, Personal Information, Tablet
Platforms: Android**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Identity Theft; IP Loss; Nuisance; Reputational Damages | - |
| Leverage | Information Disclosure; Modify configuration; Modify data; Software installation; Tampering; Dwelling | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1626` | [Mobile : Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1626) | Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can gain on a machine. Authorization has to be granted to specific users in order to perform tasks that are designated as higher risk. An adversary can use several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system. |
| `T1633` | [Mobile : Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) | Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors after checking for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware’s behavior to disengage from the victim or conceal the core functions of the payload. They may also search for VME artifacts before dropping further payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) during automated discovery to shape follow-on behaviors.   Adversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) such as checking for system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. |
| `T1417` | [Mobile : Input Capture](https://attack.mitre.org/techniques/T1417) | Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal device usage, users often provide credentials to various locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Keylogging](https://attack.mitre.org/techniques/T1417/001)) or rely on deceiving the user into providing input into what they believe to be a genuine application prompt (e.g. [GUI Input Capture](https://attack.mitre.org/techniques/T1417/002)). |
| `T1635` | [Mobile : Steal Application Access Token](https://attack.mitre.org/techniques/T1635) | Adversaries can steal user application access tokens as a means of acquiring credentials to access remote systems and resources. This can occur through social engineering or URI hijacking and typically requires user action to grant access, such as through a system “Open With” dialogue.    Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one commonly implemented framework used to issue tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry through OAuth 2.0 using a variety of authorization protocols. An example of a commonly-used sequence is Microsoft's Authorization Code Grant flow.(Citation: Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code Authorization flow - June 2019) An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested without requiring user credentials. |
| `T1426` | [Mobile : System Information Discovery](https://attack.mitre.org/techniques/T1426) | Adversaries may attempt to get detailed information about a device’s operating system and hardware, including versions, patches, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1426) during automated discovery to shape follow-on behaviors, including whether or not to fully infects the target and/or attempts specific actions.      On Android, much of this information is programmatically accessible to applications through the `android.os.Build` class. (Citation: Android-Build) iOS is much more restrictive with what information is visible to applications. Typically, applications will only be able to query the device model and which version of iOS it is running. |
| `T0869` | [Industrial : Standard Application Layer Protocol](https://attack.mitre.org/techniques/T0869) | Adversaries may establish command and control capabilities over commonly used application layer protocols such as HTTP(S), OPC, RDP, telnet, DNP3, and modbus. These protocols may be used to disguise adversary actions as benign network traffic. Standard protocols may be seen on their associated port or in some cases over a non-standard port.  Adversaries may use these protocols to reach out of the network for command and control, or in some cases to other infected devices within the network. |
| `T1641` | [Mobile : Data Manipulation](https://attack.mitre.org/techniques/T1641) | Adversaries may insert, delete, or alter data in order to manipulate external outcomes or hide activity. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.  The type of modification and the impact it will have depends on the target application, process, and the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system, typically gained through a prolonged information gathering campaign, in order to have the desired impact. |
