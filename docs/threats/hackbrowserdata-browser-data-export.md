# HackBrowserData browser data export

## Metadata
| Field | Value |
| --- | --- |
| UUID | `ba88c4a0-bf3b-46cb-b022-050ae22abce8` |
| Schema | `threat::1.0` |
| Version | `1` |
| Created | `2024-11-05` |
| Modified | `2024-11-05` |
| TLP | clear (`TLP:CLEAR`) |
| Organisation | EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`) |

## References
### Public
- **1**: [https://github.com/moonD4rk/HackBrowserData](https://github.com/moonD4rk/HackBrowserData)

## Description
HackBrowserData is a command-line tool for decrypting and exporting data
(passwords, history, cookies, bookmarks, credit cards, download history,
localStorage and extensions) from the browser. 

It supports the most popular browsers on the market and runs on Windows, macOS and Linux.

Usage examples:

## Automatic scan of the browser on the current computer, 
   outputting the decryption results in JSON format and compressing as zip.

PS C:\Users\JohnDoe\Desktop> .\hack-browser-data.exe -b all -f json --dir results --zip

PS C:\Users\JohnDoe\Desktop> ls -l .\results\
    Directory: C:\Users\JohnDoe\Desktop\results

## Run with custom browser profile folder, using the -p parameter to specify the
   path of the browser profile folder.
  
PS C:\Users\JohnDoe\Desktop> .\hack-browser-data.exe -b chrome -p "C:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default"

[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_creditcard.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_bookmark.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_cookie.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_history.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_download.csv success  
[NOTICE] [browsingdata.go:59,Output] output to file results/chrome_password.csv success

## Criticality
**High** - A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
Attacker must compromise a user endpoint and exfiltrate the browser cookies.
Cookies can be found on disk, in the process memory of the browser, and in
network traffic to remote systems.

## Surface
> **Microsoft::Microsoft 365**
> Microsoft 365 cloud-based productivity suite (formerly Office 365)

> **Azure::Security::Entra ID**
> Microsoft Entra ID in Azure (cloud identity)

> **OAuth / OIDC**
> OAuth 2.0 and OpenID Connect authorisation/authentication protocols

> **Azure**
> Microsoft Azure cloud platform

> **Windows::Desktop**
> Microsoft Windows desktop editions

> **Entra ID**
> Microsoft Entra ID (formerly Azure Active Directory)

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Identity Theft<br>Impairement | Acquisition of sufficient information and privileges to profess as a given individual, for the purpose of abusing and deceiving human trust relationships.<br>Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery. |
| Leverage | Elevation of privilege<br>Spoofing | Capacity to augment leverage over the target system by upgrading the compromised access rights<br>Threat action aimed at accessing and use of another user’s credentials, such as username and password. |
| Viability | Environment dependent | Depends |
| Kill Chain | Credential Access | Techniques resulting in the access of, or control over, system, service or domain credentials. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1111` | [Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111) | Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.   If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. (Citation: Mandiant M Trends 2011)  Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). (Citation: GCN RSA June 2011)  Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users’ phones.(Citation: Okta Scatter Swine 2022) |

## Chaining
```mermaid
flowchart LR
subgraph "Credential Access"
ba88c4a0_bf3b_46cb_b022_050ae22abce8{{"HackBrowserData browser<br>data export"}}
b0d6bf74_b204_4a48_9509_4499ed795771{{"Pass-the-cookie Attack"}}
66aafb61_9a46_4287_8b40_4785b42b77a3{{"Adversary in the Middle<br>phishing sites to bypass<br>MFA"}}
4a807ac4_f764_41b1_ae6f_94239041d349{{"MFA Bypass Techniques"}}
end
ba88c4a0_bf3b_46cb_b022_050ae22abce8 -->|implements| b0d6bf74_b204_4a48_9509_4499ed795771
b0d6bf74_b204_4a48_9509_4499ed795771 -->|succeeds| 66aafb61_9a46_4287_8b40_4785b42b77a3
b0d6bf74_b204_4a48_9509_4499ed795771 -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
66aafb61_9a46_4287_8b40_4785b42b77a3 -->|implements| 4a807ac4_f764_41b1_ae6f_94239041d349
```
### Chaining details
#### implements -> [Pass-the-cookie Attack](pass-the-cookie-attack.md) (`b0d6bf74-b204-4a48-9509-4499ed795771`) (`atomicity::implements`)
Technique used to steal browser cookies

- **Target UUID**: `b0d6bf74-b204-4a48-9509-4499ed795771`
