# Perform Microsoft Entra ID connectors MITM attack

## Metadata

- **UUID**: `f18be76e-f2b3-410a-80c5-d67e7b8e7b03`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
These connectors facilitate outbound connections to the Microsoft Entra Private 
Access and application proxy services. They must be installed on a Windows Server 
with access to backend resources. Connectors can be organized into groups to handle 
traffic to specific resources, enhancing management and optimization.  

The risks of man-in-the-middle attacks on Microsoft Entra ID connectors include the 
interception of sensitive information such as authentication tokens, usernames, passwords, 
and authentication artifacts like session cookies. Adversaries can capture this data, 
mimic legitimate users, and potentially bypass multifactor authentication requirements. 
This poses a significant threat to data confidentiality, integrity, and privacy within 
the Microsoft Entra ecosystem. 

Likewise, common techniques used in man-in-the-middle attacks on Microsoft Entra ID connectors include:

- Phishing Attacks
- Session Hijacking
- DNS Spoofing
- OAuth Application Manipulation
- DNS-over-HTTPS
- Cookie Theft
- Business Email Compromise (BEC) Attacks

## Techniques
- T1557
