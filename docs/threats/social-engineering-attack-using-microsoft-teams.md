# Social engineering attack using Microsoft Teams

## Metadata

- **UUID**: `06c60af1-5fa8-493c-bf9b-6b2e215819f1`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries are using compromised Microsoft 365 tenants to create technical
support-themed domains and send tech support lures via Microsoft Teams, 
attempting to trick users of the targeted organizations using social engineering.    

They aim to manipulate users into granting approval for multifactor authentication
(MFA) prompts, ultimately aiming to steal their credentials.    

#### Attack phases    

**Preparation phase**    

Attackers compromise an Azure tenant, rename it and add a new onmicrosoft[.]com
subdomain. It will use security-themed or product name-themed keywords to create
a new subdomain, such as teamsprotection.onmicrosoft[.]com 
Add a new user associated with that domain from which the attacker will send the
outbound message to the target tenant.    

**Social engineering phase**    

Attackers send a Teams chat message to the target from the compromised external user
masquerading as a technical support or security team; if the targeted user accepts
the message request, attackers send a Microsoft Teams message to convince the target
to enter a code into the Microsoft Authenticator app on his/her mobile device.
If the targeted user enters the code into the Authenticator app, the attacker is
granted a token to authenticate as the targeted user.    

**Post-compromise phase**    

Involves information theft from the compromised Microsoft 365 tenant, and in some 
cases, adding a device to the organisation as a managed device through Microsoft
Entra ID (formerly Azure Active Directory), likely an attempt to circumvent conditional
access policies configured to restrict access to specific resources to managed devices only.    

#### Additional Tactics: Microsoft Teams Vishing    

### Microsoft Teams Vishing    

- Attackers initiate contact via Microsoft Teams within 15-30 minutes of the email bombing.
- They pose as IT support personnel or "Help Desk Managers".
- Adversary-controlled Office 365 accounts are used, often with display names mimicking 
legitimate IT staff.
- Profile pictures and backgrounds are crafted to appear authentic.
- Attackers exploit the victim's state of confusion and urgency caused by the email bombing.

## Techniques
- T1199
