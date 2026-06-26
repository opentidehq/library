# ADFS abuse

## Metadata

- **UUID**: `19a7a12e-1c7a-4885-9359-56abd63c85c9`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2025-06-24`
- **Modified**: `2025-06-24`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.hunters.security/en/blog/adfs-threat-hunting](https://www.hunters.security/en/blog/adfs-threat-hunting)
- **2**: [https://www.beyondidentity.com/resource/active-microsoft-adfs-phishing-campaign-bypasses-mfa](https://www.beyondidentity.com/resource/active-microsoft-adfs-phishing-campaign-bypasses-mfa)
- **3**: [https://www.itpro.com/operating-systems/microsoft-windows/359365/hackers-could-abuse-legitimate-windows-ad-fs-to-steal](https://www.itpro.com/operating-systems/microsoft-windows/359365/hackers-could-abuse-legitimate-windows-ad-fs-to-steal)

## Description
AD FS (Active Directory Federation Services) is a critical identity provider solution 
for secure SSO authentication, but it presents a significant attack surface for 
threat actors. Below is a comprehensive overview of ADFS abuse threat vectors, attack 
techniques, and real-world exploitation patterns based on current research and incident data.

### Memory Adapter Manipulation

Attackers with local administrative privileges on an AD FS server can modify AD 
FS-related .NET assemblies or configuration files (such as those in the Global Assembly Cache). 
By injecting malicious code or altering authentication logic in memory or on disk, 
they can compromise the authentication process, potentially allowing unauthorised access.

### Golden SAML Attacks

Attackers can steal or forge SAML tokens by accessing the AD FS token signing certificates. 
With these certificates, they can create valid SAML tokens impersonating any user, 
granting themselves unauthorised access to federated applications (such as Microsoft 365).

### Phishing & MFA Bypass

Phishing campaigns specifically target AD FS users, tricking them into entering 
credentials on fake login pages. Once credentials are harvested, attackers may intercept 
Multi-Factor Authentication (MFA) codes or session cookies in real time, bypassing 
MFA protections.

### Information Disclosure via Vulnerabilities
  
Historical vulnerabilities (like CVE-2017-0043) have allowed authenticated attackers 
to read sensitive information from AD FS servers via crafted XML requests. While 
many such vulnerabilities are patched, they highlight the risk of information leakage.

### Credential Reuse and Lateral Movement

Attackers who obtain AD FS credentials often find that these credentials are reused 
across other systems or SSO platforms. This allows them to move laterally within 
the victim’s environment, accessing multiple services.

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Threat actors can obtain the token signing certificate and private key by abusing 
the Policy Store Transfer Service to extract the encrypted certificate, then decrypting 
it using the DKM key from Active Directory. This can be done remotely if the attacker 
has the right privileges, and once they have the private key, they can forge SAML 
tokens for any user, bypassing authentication controls.

Domains: Enterprise, SaaS
Targets: Identity Services, SAML-Joined Applications, Cloud Storage Accounts, Server Authentication
Platforms: AD FS, Active Directory, Azure AD, Office 365, Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Significant incident | A cyber attack which has a serious impact on a large organisation or on wider / local government, or which poses a considerable risk to central government or (inter)national essential services. |
| Impact | Data Breach; Identity Theft; Reputational Damages; Monetary Loss; Business disruption | - |
| Leverage | Spoofing; Tampering; Repudiation; Elevation of privilege; Information Disclosure | - |
| Viability | Likely | Probable (probably) - 55-80% |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1556` | [Modify Authentication Process](https://attack.mitre.org/techniques/T1556) | Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using [Valid Accounts](https://attack.mitre.org/techniques/T1078).  Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. |
| `T1133` | [External Remote Services](https://attack.mitre.org/techniques/T1133) | Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)  Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.  Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware) |
| `T1606.002` | [Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002) | An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate.(Citation: Microsoft SolarWinds Steps) The default lifetime of a SAML token is one hour, but the validity period can be specified in the <code>NotOnOrAfter</code> value of the <code>conditions ...</code> element in a token. This value can be changed using the <code>AccessTokenLifetime</code> in a <code>LifetimeTokenPolicy</code>.(Citation: Microsoft SAML Token Lifetimes) Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism.(Citation: Cyberark Golden SAML)  An adversary may utilize [Private Keys](https://attack.mitre.org/techniques/T1552/004) to compromise an organization's token-signing certificate to create forged SAML tokens. If the adversary has sufficient permissions to establish a new federation trust with their own Active Directory Federation Services (AD FS) server, they may instead generate their own trusted token-signing certificate.(Citation: Microsoft SolarWinds Customer Guidance) This differs from [Steal Application Access Token](https://attack.mitre.org/techniques/T1528) and other similar behaviors in that the tokens are new and forged by the adversary, rather than stolen or intercepted from legitimate users.  An adversary may gain administrative Entra ID privileges if a SAML token is forged which claims to represent a highly privileged account. This may lead to [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Microsoft SolarWinds Customer Guidance) |
