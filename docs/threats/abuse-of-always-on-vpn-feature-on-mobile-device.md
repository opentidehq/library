# Abuse of 'Always-on VPN' feature on mobile device

## Metadata

- **UUID**: `80329dfd-eb12-49da-9f20-565758b55eab`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-04-23`
- **Modified**: `2025-04-23`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Maxime%20Clementz%20-%20Defeating%20VPN%20Always-On.pdf](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Maxime%20Clementz%20-%20Defeating%20VPN%20Always-On.pdf)
- **2**: [https://celestix.com/docs/security-considerations-for-always-on-vpn-deployments/](https://celestix.com/docs/security-considerations-for-always-on-vpn-deployments/)
- **3**: [https://www.bleepingcomputer.com/news/google/android-leaks-some-traffic-even-when-always-on-vpn-is-enabled/](https://www.bleepingcomputer.com/news/google/android-leaks-some-traffic-even-when-always-on-vpn-is-enabled/)

## Description
The "Always-on VPN" feature on mobile devices is designed to ensure that all network 
traffic is routed through a VPN tunnel, providing continuous privacy and security. 
However, this feature can introduce specific threat vectors if abused or improperly implemented.

### Key Threat Vectors and Risks

- **Malicious VPN Apps and Abuse of Permissions**  
  Many VPN apps, especially on Android, have been found to abuse the permissions 
  granted by the VPN service. Malicious or poorly designed VPN apps can:
  - Harvest sensitive user data (such as SMS history and contact lists).
  - Inject code or malware into network traffic.
  - Route user traffic through untrusted third-party servers.
  - Intercept sensitive information, including banking and social network credentials.
  
The "Always-on VPN" feature, if enabled with a malicious app, ensures that *all* 
device traffic is exposed to the app, amplifying the potential for abuse and data exfiltration.

- **Traffic Leakage Despite 'Always-on VPN'**  
  On Android, even with "Always-on VPN" and the "Block connections without VPN" 
  (VPN Lockdown) feature enabled, some traffic can leak outside the VPN tunnel. 
  This leakage occurs particularly when:
  - The device connects to a new WiFi network and performs connectivity checks 
  (such as checking for captive portals).
  - The leaked data can include source IP addresses, DNS lookups, HTTPS, and NTP traffic.
  
This is a design choice in Android, and such leaks may expose user information or 
device identifiers to local networks or attackers, undermining the privacy guarantees 
of the VPN.

- **Split Tunneling and Unintended Bypasses**  
  Some VPN apps or device configurations allow for split tunneling, where only certain 
  traffic goes through the VPN. If misconfigured, sensitive data may bypass the VPN, 
  exposing it to interception on insecure networks.

- **Device Compromise and Credential Theft**  
  If a device with Always-on VPN is compromised (e.g., stolen or infected with malware), 
  attackers could potentially exploit the persistent VPN connection to maintain 
  access to internal networks or exfiltrate data. While certificate revocation and 
  account disabling can mitigate this, there is a window of risk before such actions are taken.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Adversaries must obtain valid user or device credentials, or compromise authentication 
certificates used for VPN access. This could be achieved through phishing, credential 
theft, or exploiting weak authentication practices.

Domains: Mobile
Targets: Mobile phone, Tablet, VPN Client, Personal Information
Platforms: iOS, Android**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Competitive disadvantage; Data Breach; Identity Theft; IP Loss | - |
| Leverage | Dwelling; Information Disclosure; Spoofing | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Persistence | Any access, action or change to a system that gives an attacker persistent presence on the system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1133` | [External Remote Services](https://attack.mitre.org/techniques/T1133) | Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)  Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.  Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware) |
| `T1078` | [Valid Accounts](https://attack.mitre.org/techniques/T1078) | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.(Citation: volexity_0day_sophos_FW) Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.  In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.(Citation: CISA MFA PrintNightmare)  The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.(Citation: TechNet Credential Theft) |
| `T1195` | [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) | Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.  Supply chain compromise can take place at any stage of the supply chain including:  * Manipulation of development tools * Manipulation of a development environment * Manipulation of source code repositories (public or private) * Manipulation of source code in open-source dependencies * Manipulation of software update/distribution mechanisms * Compromised/infected system images (multiple cases of removable media infected at the factory)(Citation: IBM Storwize)(Citation: Schneider Electric USB Malware)  * Replacement of legitimate software with modified versions * Sales of modified/counterfeit products to legitimate distributors * Shipment interdiction  While supply chain compromise can impact any component of hardware or software, adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.(Citation: Avast CCleaner3 2018)(Citation: Microsoft Dofoil 2018)(Citation: Command Five SK 2011) Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.(Citation: Symantec Elderwood Sept 2012)(Citation: Avast CCleaner3 2018)(Citation: Command Five SK 2011) Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise) |
| `T1199` | [Trusted Relationship](https://attack.mitre.org/techniques/T1199) | Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.  Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, [Valid Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to internal network systems may be compromised and used.(Citation: CISA IT Service Providers)  In Office 365 environments, organizations may grant Microsoft partners or resellers delegated administrator permissions. By compromising a partner or reseller account, an adversary may be able to leverage existing delegated administrator relationships or send new delegated administrator offers to clients in order to gain administrative control over the victim tenant.(Citation: Office 365 Delegated Administration) |
