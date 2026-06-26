# Rogue access point

## Metadata

- **UUID**: `bdb9fd43-a9f9-4026-84a5-0b52d3b0243b`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-04-24`
- **Modified**: `2025-04-24`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.verimatrix.com/cybersecurity/knowledge-base/rogue-access-points-what-they-are-and-how-to-stop-them/](https://www.verimatrix.com/cybersecurity/knowledge-base/rogue-access-points-what-they-are-and-how-to-stop-them/)
- **2**: [https://www.accessagility.com/rogue-wifi-wireless-access-point-ap](https://www.accessagility.com/rogue-wifi-wireless-access-point-ap)
- **3**: [https://zimperium.com/glossary/rogue-access-point/](https://zimperium.com/glossary/rogue-access-point/)
- **4**: [https://jumpcloud.com/it-index/what-is-a-rogue-access-point](https://jumpcloud.com/it-index/what-is-a-rogue-access-point)

## Description
A rogue access point (AP) is any wireless access point connected to a network without 
explicit authorization from network administrators. These unauthorized devices 
can be set up deliberately by attackers or unintentionally by employees, and they 
bypass the security controls and configurations established by IT teams, exposing 
the network to significant risks.

### How Rogue Access Points Work

- **Impersonation:** Rogue APs may mimic legitimate networks by copying the Service 
Set Identifier (SSID), tricking users into connecting to them.
- **Open Access:** Many operate without passwords or encryption, making them easy 
for devices to discover and connect to, but extremely vulnerable.
- **Traffic Interception:** Once connected, attackers can intercept all data transmitted, 
including credentials and confidential information, using packet sniffing tools.
- **Attack Platform:** They serve as a launchpad for further attacks such as man-in-the-middle (MitM), 
malware distribution, phishing, and ransomware deployment.

### Risks and Threats

- **Data Interception & Theft:** Sensitive information, such as login credentials, 
financial data, and confidential documents, can be captured.
- **Man-in-the-Middle Attacks:** Attackers can intercept, modify, or inject data 
into communications, hijack sessions, and steal credentials.
- **Malware Distribution:** Rogue APs can be used to distribute malware or ransomware 
to connected devices.
- **Credential Theft:** Users may unknowingly submit credentials to attackers.
- **Network Disruption:** Rogue APs can interfere with legitimate network operations, 
causing downtime and instability.
- **Regulatory Compliance Violations:** Industries with strict data regulations 
(e.g., healthcare, finance) risk non-compliance and potential fines if rogue APs are present.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries must be within range of the target network to deploy or broadcast their 
rogue AP. This could mean physical access to the premises (to connect a device to 
the wired network) or being close enough to broadcast a Wi-Fi signal that clients 
can detect and join.

Domains: Mobile, Enterprise
Targets: Laptop, Mobile phone, Tablet, Router or switch, Personal Information, Critical Documents
Platforms: macOS, Windows, Linux, Android, iOS**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Competitive disadvantage; Data Breach; Identity Theft; IP Loss; Reputational Damages | - |
| Leverage | Dwelling; Information Disclosure; Spoofing; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Collection | Techniques used to identify and gather data from a target network prior to exfiltration. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T0860` | [Industrial : Wireless Compromise](https://attack.mitre.org/techniques/T0860) | Adversaries may perform wireless compromise as a method of gaining communications and unauthorized access to a wireless network. Access to a wireless network may be gained through the compromise of a wireless device. (Citation: Alexander Bolshev, Gleb Cherbov July 2014) (Citation: Alexander Bolshev March 2014) Adversaries may also utilize radios and other wireless communication devices on the same frequency as the wireless network. Wireless compromise can be done as an initial access vector from a remote distance.   A Polish student used a modified TV remote controller to gain access to and control over the Lodz city tram system in Poland. (Citation: John Bill May 2017) (Citation: Shelley Smith February 2008) The remote controller device allowed the student to interface with the trams network to modify track settings and override operator control. The adversary may have accomplished this by aligning the controller to the frequency and amplitude of IR control protocol signals. (Citation: Bruce Schneier January 2008) The controller then enabled initial access to the network, allowing the capture and replay of tram signals. (Citation: John Bill May 2017) |
| `T1422.002` | [Mobile : Wi-Fi Discovery](https://attack.mitre.org/techniques/T1422/002) | Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems. Adversaries may use Wi-Fi information as part of [Discovery](https://attack.mitre.org/tactics/TA0032) or [Credential Access](https://attack.mitre.org/tactics/TA0031) activity to support both ongoing and future campaigns. |
| `T1638` | [Mobile : Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) | Adversaries may attempt to position themselves between two or more networked devices to support follow-on behaviors such as [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002) or [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1642).       [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) can be achieved through several mechanisms. For example, a malicious application may register itself as a VPN client, effectively redirecting device traffic to adversary-owned resources. Registering as a VPN client requires user consent on both Android and iOS; additionally, a special entitlement granted by Apple is needed for iOS devices. Alternatively, a malicious application with escalation privileges may utilize those privileges to gain access to network traffic.       Specific to Android devices, adversary-in-the-disk is a type of AiTM attack where adversaries monitor and manipulate data that is exchanged between applications and external storage.(Citation: mitd_kaspersky)(Citation: mitd_checkpoint)(Citation: mitd_checkpoint_research) To accomplish this, a malicious application firsts requests for access to multimedia files on the device (`READ_EXTERNAL STORAGE` and `WRITE_EXTERNAL_STORAGE`), then the application reads data on the device and/or writes malware to the device. Though the request for access is common, when used maliciously, adversaries may access files and other sensitive data due to abusing the permission. Multiple applications were shown to be vulnerable against this attack; however, scrutiny of permissions and input validations may mitigate this attack.      Outside of a mobile device, adversaries may be able to capture traffic by employing a rogue base station or Wi-Fi access point. These devices will allow adversaries to capture network traffic after it has left the device, while it is flowing to its destination. On a local network, enterprise techniques could be used, such as [ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) or [DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003).       If applications properly encrypt their network traffic, sensitive data may not be accessible to adversaries, depending on the point of capture. For example, properly implementing Apple’s Application Transport Security (ATS) and Android’s Network Security Configuration (NSC) may prevent sensitive data leaks.(Citation: NSC_Android) |
| `T1557.004` | [Adversary-in-the-Middle: Evil Twin](https://attack.mitre.org/techniques/T1557/004) | Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or [Input Capture](https://attack.mitre.org/techniques/T1056).(Citation: Australia ‘Evil Twin’)  By using a Service Set Identifier (SSID) of a legitimate Wi-Fi network, fraudulent Wi-Fi access points may trick devices or users into connecting to malicious Wi-Fi networks.(Citation: Kaspersky evil twin)(Citation: medium evil twin)  Adversaries may provide a stronger signal strength or block access to Wi-Fi access points to coerce or entice victim devices into connecting to malicious networks.(Citation: specter ops evil twin)  A Wi-Fi Pineapple – a network security auditing and penetration testing tool – may be deployed in Evil Twin attacks for ease of use and broader range. Custom certificates may be used in an attempt to intercept HTTPS traffic.   Similarly, adversaries may also listen for client devices sending probe requests for known or previously connected networks (Preferred Network Lists or PNLs). When a malicious access point receives a probe request, adversaries can respond with the same SSID to imitate the trusted, known network.(Citation: specter ops evil twin)  Victim devices are led to believe the responding access point is from their PNL and initiate a connection to the fraudulent network.  Upon logging into the malicious Wi-Fi access point, a user may be directed to a fake login page or captive portal webpage to capture the victim’s credentials. Once a user is logged into the fraudulent Wi-Fi network, the adversary may able to monitor network activity, manipulate data, or steal additional credentials. Locations with high concentrations of public Wi-Fi access, such as airports, coffee shops, or libraries, may be targets for adversaries to set up illegitimate Wi-Fi access points. |
