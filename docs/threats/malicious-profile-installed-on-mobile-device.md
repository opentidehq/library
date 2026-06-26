# Malicious profile installed on mobile device

## Metadata

- **UUID**: `b8740296-9d34-453b-8127-b5d8659a6138`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-04-14`
- **Modified**: `2025-04-14`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://my-last-and-only.blogspot.com/2013/04/malicious-profiles-sleeping-giant-of.html](https://my-last-and-only.blogspot.com/2013/04/malicious-profiles-sleeping-giant-of.html)
- **2**: [https://www.ifsecglobal.com/cyber-security/apple-ios-vulnerable-hidden-profile-attacks/](https://www.ifsecglobal.com/cyber-security/apple-ios-vulnerable-hidden-profile-attacks/)
- **3**: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)

## Description
A "malicious profile" refers to a configuration file installed on a mobile device 
that compromises its security and privacy. These profiles exploit the device's settings 
to grant attackers unauthorized control or access to sensitive data, making them 
a serious threat vector for mobile devices.

### How Malicious Profiles Are Installed

Attackers use various techniques to deploy malicious profiles on devices:

1. **Phishing Attacks**: Victims are tricked into clicking links or downloading 
files via phishing emails or websites. These links often promise to fix security 
issues or provide valuable services, convincing users to install the malicious profile.

2. **Social Engineering**: Attackers manipulate users into believing the profile 
is legitimate, often using fake security alerts or enticing offers.

3. **Man-in-the-Middle (MitM) Attacks**: Over unsecured Wi-Fi networks, attackers 
intercept communications and install malicious profiles by redirecting traffic through 
spoofed hotspots.

4. **Third-Party App Stores**: Android users may unknowingly install malicious apps 
containing configuration profiles from unverified sources.

### Implications of Malicious Profiles

Malicious profiles can severely compromise a device's security, privacy, and functionality:

1. **Persistent Control**: Once installed, these profiles often cannot be removed 
manually, allowing attackers long-term control over the device settings.

2. **Data Interception**:
  - Profiles may configure devices to route traffic through malicious VPNs or proxy 
  servers, enabling attackers to intercept and decrypt sensitive information such 
  as emails, banking credentials, and social media passwords.
  - Installation of untrusted root certificates allows attackers to bypass TLS/SSL 
  encryption and impersonate secure websites.

3. **Surveillance Capabilities**:
  - Attackers can record conversations, monitor messages, and even capture audio 
  from the environment using malicious profiles.
  - Corporate devices are particularly vulnerable as attackers may redirect email 
  traffic or manipulate enterprise configurations.

4. **Device Misconfiguration**:
  - Malicious profiles can alter Wi-Fi settings, enforce insecure passcodes, or 
  disable security apps, weakening the device’s overall security posture.

5. **Persistence for Future Attacks**:
  - By tampering with trust settings (e.g., certificates), attackers ensure that 
  the device implicitly trusts them for future actions without user intervention.

### Examples of Exploits

- **iOS Devices**:
  Attackers exploit configuration vulnerabilities by installing untrusted profiles 
  that intercept secure connections and manipulate user sessions. For example, phishing 
  campaigns may trick users into downloading profiles that hijack email traffic 
  or steal credentials.

- **Android Devices**:
  Malware such as "Godless" exploits older Android versions by embedding malicious 
  configuration files within apps downloaded from third-party stores. These files 
  gain root access and install spyware for complete device takeover.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries rely on social engineering (e.g., phishing emails/SMS with fake security alerts), 
and infrastructure such as spoofed domains, third-party app stores, or MitM tools 
to distribute payloads or force installations.

Domains: Mobile
Targets: Mobile phone, Tablet, Personal Information, Critical Documents
Platforms: Android, iOS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Asset and fraud; Data Breach; Identity Theft; IP Loss; Nuisance | - |
| Leverage | Information Disclosure; Modify configuration; Modify privileges; Spoofing | - |
| Viability | Likely | Probable (probably) - 55-80% |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1456` | [Mobile : Drive-By Compromise](https://attack.mitre.org/techniques/T1456) | Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring an [Application Access Token](https://attack.mitre.org/techniques/T1550/001).  Multiple ways of delivering exploit code to a browser exist, including:  * A legitimate website is compromised where adversaries have injected some form of malicious code such as JavaScript, iFrames, and cross-site scripting. * Malicious ads are paid for and served through legitimate ad providers. * Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client (e.g. forum posts, comments, and other user controllable web content).  Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.(Citation: Lookout-StealthMango)  Typical drive-by compromise process:  1. A user visits a website that is used to host the adversary controlled content. 2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version.      * The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes. 3. Upon finding a vulnerable version, exploit code is delivered to the browser. 4. If exploitation is successful, then it will give the adversary code execution on the user's system unless other protections are in place.     * In some cases a second visit to the website after the initial scan is required before exploit code is delivered. |
| `T1624` | [Mobile : Event Triggered Execution](https://attack.mitre.org/techniques/T1624) | Adversaries may establish persistence using system mechanisms that trigger execution based on specific events. Mobile operating systems have means to subscribe to events such as receiving an SMS message, device boot completion, or other device activities.   Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via automatically and repeatedly executing malicious code. After gaining access to a victim’s system, adversaries may create or modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked. |
| `T1631.001` | [Mobile : Ptrace System Calls](https://attack.mitre.org/techniques/T1631/001) | Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.    Ptrace system call injection involves attaching to and modifying a running process. The ptrace system call enables a debugging process to observe and control another process (and each individual thread), including changing memory and register values.(Citation: PTRACE man) Ptrace system call injection is commonly performed by writing arbitrary code into a running process (e.g., by using `malloc`) then invoking that memory with `PTRACE_SETREGS` to set the register containing the next instruction to execute. Ptrace system call injection can also be done with `PTRACE_POKETEXT`/`PTRACE_POKEDATA`, which copy data to a specific address in the target process's memory (e.g., the current address of the next instruction).(Citation: PTRACE man)(Citation: Medium Ptrace JUL 2018)    Ptrace system call injection may not be possible when targeting processes with high-privileges, and on some systems those that are non-child processes.(Citation: BH Linux Inject)    Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via ptrace system call injection may also evade detection from security products since the execution is masked under a legitimate process. |
| `T1407` | [Mobile : Download New Code at Runtime](https://attack.mitre.org/techniques/T1407) | Adversaries may download and execute dynamic code not included in the original application package after installation. This technique is primarily used to evade static analysis checks and pre-publication scans in official app stores. In some cases, more advanced dynamic or behavioral analysis techniques could detect this behavior. However, in conjunction with [Execution Guardrails](https://attack.mitre.org/techniques/T1627) techniques, detecting malicious code downloaded after installation could be difficult.  On Android, dynamic code could include native code, Dalvik code, or JavaScript code that utilizes Android WebView’s `JavascriptInterface` capability.   On iOS, dynamic code could be downloaded and executed through 3rd party libraries such as JSPatch. (Citation: FireEye-JSPatch) |
| `T1417` | [Mobile : Input Capture](https://attack.mitre.org/techniques/T1417) | Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal device usage, users often provide credentials to various locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Keylogging](https://attack.mitre.org/techniques/T1417/001)) or rely on deceiving the user into providing input into what they believe to be a genuine application prompt (e.g. [GUI Input Capture](https://attack.mitre.org/techniques/T1417/002)). |
