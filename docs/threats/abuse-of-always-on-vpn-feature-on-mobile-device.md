# Abuse of 'Always-on VPN' feature on mobile device

## Metadata

- **UUID**: `80329dfd-eb12-49da-9f20-565758b55eab`
- **Schema**: `threat::1.0`
- **TLP**: clear

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

## Techniques
- T1133
- T1078
- T1195
- T1199
