# Password spraying attack

## Metadata

- **UUID**: `cc546bbc-f71c-4538-934c-415d6adc293b`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Password spraying is a technique that attackers use to try a small list
of common or expected passwords against a set of usernames. This technique
is used to avoid account lockouts that would normally occur when brute
forcing a single account with many passwords1. Password spraying is a
sub-technique of credential spraying, which is just credential guessing
but "sprayed" (i.e. against multiple accounts). (ref [1], [2])  

Adversaries have been observed using password spray attacks to exploit
logins of network services or credential harvesting, typically used
to obtain initial foothold.

They attempt username and password combinations in a slow manner,
researching the pattern for valid accounts (e.g. email address or username
length). Organizations targeted typically see a few authentication attempts
per account; with nearly every attempt originating from constantly rotating
IP addresses, many associated with the Tor anonymizing service.  

Some strategies conducted by adversaries are:  

- Credential stuffing towards Microsoft Office 365 accounts, there are
tools that identify valid credentials for Office 365 and Azure AD accounts,
as Spray365.  

- Abuse of Exchange servers. There are tools for searching through email
in an Exchange environment for specific terms (passwords, insider intel,
network architecture information, etc.) as for example MailSniper; which
includes modules for password spraying, enumerating users and domains or
gathering the Global Address List (GAL) from OWA and EWS.  

- Password spray against exposed Active Directory Federation Services
(ADFS) infrastructure. The organizations not using MFA have a higher risk
of having accounts compromised through password spray. If attack is
successful, adversaries may look for additional contacts, sensitive
information, privileged information, or send phishing links to
others in the organization.  


- Password spraying attack against Microsoft Entra ID applications
Password spray attacks involve trying a few common passwords against
specific or many accounts. This may include and attack against the
cloud-based Microsoft application solution: Microsoft Entra ID. The
goal is to bypass traditional protections like password lockout and
malicious IP blocking. They can include low number of login attempts
or lack of consistency which makes them difficult to detect.

## Techniques
- T1110.003
