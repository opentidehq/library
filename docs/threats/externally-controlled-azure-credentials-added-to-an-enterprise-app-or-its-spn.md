# Externally controlled Azure credentials added to an Enterprise app or its SPN

## Metadata

- **UUID**: `ca2751c7-8641-4fb0-a90b-30c5987015dc`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors may assign valid azure credentials to an Azure Enterprise App or its SPN (service
principal). NSA writes in its advisory that the app was seen leveraged
to access emails from the Enterprise app, but the attack vector could be
used for many other types of leverage.

## Techniques
- T1098.003
