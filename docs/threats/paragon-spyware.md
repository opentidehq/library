# Paragon Spyware

## Metadata

- **UUID**: `e1741a76-3df1-430a-8dda-5c6bc9c3e1dd`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-03-26`
- **Modified**: `2025-03-26`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.bleepingcomputer.com/news/security/whatsapp-patched-zero-day-flaw-used-in-paragon-spyware-attacks/](https://www.bleepingcomputer.com/news/security/whatsapp-patched-zero-day-flaw-used-in-paragon-spyware-attacks/)
- **2**: [https://www.schneier.com/blog/archives/2025/03/report-on-paragon-spyware.html](https://www.schneier.com/blog/archives/2025/03/report-on-paragon-spyware.html)
- **3**: [https://www.ynetnews.com/business/article/ryc4uibikl](https://www.ynetnews.com/business/article/ryc4uibikl)
- **4**: [https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/](https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/)

## Description
Paragon Spyware, also known as Graphite, is a sophisticated surveillance tool developed 
by Paragon Solutions, an Israeli company founded in 2019. This spyware is designed to infiltrate 
encrypted messaging apps such as WhatsApp, Signal, Facebook Messenger, and Gmail, allowing 
law enforcement and intelligence agencies to intercept private communications.    

## Key Features    

- **Zero-Click Exploit**: Graphite uses a "zero-click" method, meaning it can infect 
a device without any action from the target.
- **WhatsApp Vulnerability**: The spyware exploits a vulnerability in WhatsApp, 
using a malicious PDF file to gain access to the device.
- **Data Extraction**: Once installed, Graphite can extract stored files, photos, 
and monitor communications across various platforms.
- **Cloud Upload**: The extracted data is uploaded to a cloud server, leaving no 
traces on the infected device.
- **Sandbox Escape**: The spyware can escape the Android sandbox to compromise other 
apps on the targeted devices.    

## Recent Developments    

In January 2025, WhatsApp patched a zero-day vulnerability that was being exploited 
by Paragon Spyware. The company notified approximately 90 Android users from over 
20 countries who were targeted, including journalists and activists.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Attackers add targets to a WhatsApp group and send a PDF file. When the device automatically 
processes the PDF, it exploits a vulnerability to load the Graphite spyware

Domains: Mobile
Targets: Mobile phone, Personal Information, Tablet, Identity Services
Platforms: iOS, Android**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Competitive disadvantage; Data Breach; IP Loss; Identity Theft | - |
| Leverage | Spoofing; Tampering; Information Disclosure; Software installation | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1430` | [Mobile : Location Tracking](https://attack.mitre.org/techniques/T1430) | Adversaries may track a device’s physical location through use of standard operating system APIs via malicious or exploited applications on the compromised device.      On Android, applications holding the `ACCESS_COAURSE_LOCATION` or `ACCESS_FINE_LOCATION` permissions provide access to the device’s physical location. On Android 10 and up, declaration of the `ACCESS_BACKGROUND_LOCATION` permission in an application’s manifest will allow applications to request location access even when the application is running in the background.(Citation: Android Request Location Permissions) Some adversaries have utilized integration of Baidu map services to retrieve geographical location once the location access permissions had been obtained.(Citation: PaloAlto-SpyDealer)(Citation: Palo Alto HenBox)      On iOS, applications must include the `NSLocationWhenInUseUsageDescription`, `NSLocationAlwaysAndWhenInUseUsageDescription`, and/or `NSLocationAlwaysUsageDescription` keys in their `Info.plist` file depending on the extent of requested access to location information.(Citation: Apple Requesting Authorization for Location Services) On iOS 8.0 and up, applications call `requestWhenInUseAuthorization()` to request access to location information when the application is in use or `requestAlwaysAuthorization()` to request access to location information regardless of whether the application is in use. With elevated privileges, an adversary may be able to access location data without explicit user consent with the `com.apple.locationd.preauthorized` entitlement key.(Citation: Google Project Zero Insomnia) |
| `T1636.003` | [Mobile : Contact List](https://attack.mitre.org/techniques/T1636/003) | Adversaries may utilize standard operating system APIs to gather contact list data. On Android, this can be accomplished using the Contacts Content Provider. On iOS, this can be accomplished using the `Contacts` framework.      If the device has been jailbroken or rooted, an adversary may be able to access the [Contact List](https://attack.mitre.org/techniques/T1636/003) without the user’s knowledge or approval. |
| `T1189` | [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) | Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. Multiple ways of delivering exploit code to a browser exist (i.e., [Drive-by Target](https://attack.mitre.org/techniques/T1608/004)), including:  * A legitimate website is compromised, allowing adversaries to inject malicious code * Script files served to a legitimate website from a publicly writeable cloud storage bucket are modified by an adversary * Malicious ads are paid for and served through legitimate ad providers (i.e., [Malvertising](https://attack.mitre.org/techniques/T1583/008)) * Built-in web application interfaces that allow user-controllable content are leveraged for the insertion of malicious scripts or iFrames (e.g., cross-site scripting)  Browser push notifications may also be abused by adversaries and leveraged for malicious code injection via [User Execution](https://attack.mitre.org/techniques/T1204). By clicking "allow" on browser push notifications, users may be granting a website permission to run JavaScript code on their browser.(Citation: Push notifications - viruspositive)(Citation: push notification -mcafee)(Citation: push notifications - malwarebytes)  Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or a particular region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is often referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.(Citation: Shadowserver Strategic Web Compromise)  Typical drive-by compromise process:  1. A user visits a website that is used to host the adversary controlled content. 2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. The user may be required to assist in this process by enabling scripting, notifications, or active website components and ignoring warning dialog boxes. 3. Upon finding a vulnerable version, exploit code is delivered to the browser. 4. If exploitation is successful, the adversary will gain code execution on the user's system unless other protections are in place. In some cases, a second visit to the website after the initial scan is required before exploit code is delivered.  Unlike [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ. |
| `T1513` | [Mobile : Screen Capture](https://attack.mitre.org/techniques/T1513) | Adversaries may use screen capture to collect additional information about a target device, such as applications running in the foreground, user data, credentials, or other sensitive information. Applications running in the background can capture screenshots or videos of another application running in the foreground by using the Android `MediaProjectionManager` (generally requires the device user to grant consent).(Citation: Fortinet screencap July 2019)(Citation: Android ScreenCap1 2019) Background applications can also use Android accessibility services to capture screen contents being displayed by a foreground application.(Citation: Lookout-Monokle) An adversary with root access or Android Debug Bridge (adb) access could call the Android `screencap` or `screenrecord` commands.(Citation: Android ScreenCap2 2019)(Citation: Trend Micro ScreenCap July 2015) |
| `T1633` | [Mobile : Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) | Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors after checking for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware’s behavior to disengage from the victim or conceal the core functions of the payload. They may also search for VME artifacts before dropping further payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) during automated discovery to shape follow-on behaviors.   Adversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) such as checking for system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. |
| `T1068` | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) | Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.  When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods.  Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020) Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) or [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570). |
