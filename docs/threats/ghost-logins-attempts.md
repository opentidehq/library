# Ghost logins attempts

## Metadata

- **UUID**: `6e988fa7-69c9-4aef-897c-a34fa5066dac`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Ghost logins is a technique that exploits the fact that SaaS user accounts
often enable multiple simultaneous logins using different sign-in methods. 

Ghost logins can be used for both the initial access and persistence stages of
a cyber attack, doubling up as a defense evasion technique because of low login
method visibility.

For initial access, the technique exploits the fact that local and SSO logins
can exist simultaneously. Given that many apps are self-adopted by users, it is
likely that many users will default to a local username and password login at 
this stage. If the app is later adopted companywide and brought into SSO,
the original local login will continue to exist unless explicitly disabled or deleted.

Because MFA is applied at the app and IdP level independently, it is possible to
end up with an SSO login that requires MFA (via the IdP login), but a local
login that does not. This creates an easy target identity for attackers to look for.

When combined with other identity vulnerabilities such as weak, breached, and/or
reused passwords, attackers can easily automate ghost login discovery and
exploitation at scale.  

Ghost logins can also be created after an attacker has established access to an app.
For example, if a social login is used to access an account, an adversary may be 
able to configure a separate username/password login, or even connect a second
social account that the adversary controls.

If the account has sufficient privileges, it may also be possible to set up or
change the SAML login settings to inject a malicious URL, for example to an
attacker controlled tenant.

## Techniques
- T1556
- T1078.003

## Chaining
```mermaid
flowchart LR
6e988fa7_69c9_4aef_897c_a34fa5066dac["Ghost logins attempts"]
4a807ac4_f764_41b1_ae6f_94239041d349["MFA Bypass Techniques"]
6e988fa7_69c9_4aef_897c_a34fa5066dac --> 4a807ac4_f764_41b1_ae6f_94239041d349
```
