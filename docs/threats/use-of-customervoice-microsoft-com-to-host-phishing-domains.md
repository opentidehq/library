# Use of customervoice.microsoft.com to host Phishing domains

## Metadata

- **UUID**: `cef11e0a-32c7-46c6-8c9c-667d0f1055e2`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
This threat vector is based on real phishing domains built and utilized by
a real, still unknown threat actor. The subdomain 
customervoice.microsoft.com should be blocked on forward proxies by most 
organizations, unless they have legit reasons to have traffic to this, and
legit traffic going there.

## Techniques
- T1566.002
- T1566.003
