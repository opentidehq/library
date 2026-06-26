# iOS Trojan harvesting facial recognition data

## Metadata

- **UUID**: `9e93dc4d-486b-43b7-aab7-d3a336a6a72e`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
The GoldPickaxe Malware Analysis provides an in-depth look at the capabilities of 
a new iOS Trojan named GoldPickaxe.iOS, which is part of a broader suite of malware 
developed by the Chinese-speaking cybercriminal group codenamed GoldFactory.  

GoldPickaxe.iOS is capable of collecting sensitive data, including facial recognition 
data, identity documents, and SMS messages. The Android version, GoldPickaxe.Android, 
shares similar functionalities. The malware exploits AI-driven face-swapping services 
to create deepfakes, enabling unauthorized access to victims' banking accounts, 
a novel technique in cyber theft.  

The initial distribution methods for GoldPickaxe.iOS include:

- Apple's TestFlight platform, where they trick users to download a TestFlight
  app from hxxps://testflight.apple[.]com/join/<ID>.

- Use of social engineering to install a Mobile Device Management (MDM) profile on
  user devices, granting them full control. At any time only one MDM profile can
  be active, but to have several MDM profiles installed in the device is possible.  

The infection chain involves several steps, including receiving a link that leads 
to a fraudulent website, being prompted to install an MDM profile, and granting 
the adversaries control over the device. Once installed, the malware can perform
various malicious activities, including tracking, remote wiping, and installing
additional apps without the user's consent.

## Techniques
- T1566.001
- T1566.002
- T1078
- T1404
