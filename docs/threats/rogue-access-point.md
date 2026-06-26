# Rogue access point

## Metadata

- **UUID**: `bdb9fd43-a9f9-4026-84a5-0b52d3b0243b`
- **Schema**: `threat::1.0`
- **TLP**: clear

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

## Techniques
- T0860
- T1422.002
- T1638
- T1557.004
