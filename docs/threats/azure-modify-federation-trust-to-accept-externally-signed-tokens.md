# Azure - Modify federation trust to accept externally signed tokens

## Metadata

- **UUID**: `9bb31c65-8abd-48fc-afe3-8aca76109737`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Once they acquired sufficient priviledges,attackers add their own certificate as 
a trusted entity in the domain either by adding a new federation trust to 
an existing tenant or modifying the properties of an existing federation 
trust. As a result, any SAML token they create and sign will be valid for 
the identity of their choosing. This attack may be performed as an alternative
to the Golden SAML attack to gain persistent access without having to sign 
the SAML response at each access request, while needing the same amount of control 
over the ADFS server.

## Techniques
- T1484.002
