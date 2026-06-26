# Phishing with Azure AD B2B Collaboration

## Metadata

- **UUID**: `f9a6f927-d08c-40c1-85af-01331c471def`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Phishing with Azure AD B2B Collaboration involves exploiting the service to send 
malicious invitations that appear to come from Microsoft or other third-parties,
making it difficult for the user to detect that it is not legitimate.
Here are the key points:

### Malicious Invitations 
Adversaries can create a free trial for Azure AD Premium and set up an Enterprise App 
with single sign-on (SSO) through a user-defined URL, which can be the adversary 
own website. This app can then be assigned to new users, allowing the adversaries to 
insert phishing recipients[1].

### Email Elements
The invitation email typically includes a warning about phishing, but the email 
itself appears legitimate. It is sent from a Microsoft address and includes a link 
to a landing page that may redirect users to the adversary site. The email may 
also include the inviter name and profile image for added credibility[3].

### Authentication Flow 
When a user accepts the invitation, they are redirected to the adversary site, 
may look like a legitimate Microsoft page. This can be achieved by creating an 
outdated OneDrive logo or using a well-known brand name in the Entra ID organization[1].

### Technical Details 
The phishing campaign can be set up using PowerShell commands to manage Azure AD 
and MSOnline modules. The adversaries can also use the Create invitation API to 
customize the invitation message and ensure it appears legitimate[2][4].

## Techniques
- T1566
