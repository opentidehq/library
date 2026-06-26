# GSM interception

## Metadata

- **UUID**: `5238718b-13c4-46d7-a84c-d29c77e5d801`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
GSM interception refers to the unauthorized capture and monitoring of communications 
(calls, SMS, and sometimes data) transmitted over GSM (Global System for Mobile Communications) 
networks. This threat vector exploits inherent weaknesses in the GSM protocol, outdated 
encryption algorithms, and the ability to impersonate legitimate network infrastructure.

## How GSM interception works

**Key Techniques:**

- **IMSI Catchers (Fake Base Stations):** Attackers deploy rogue base stations 
(often called IMSI catchers or Stingrays) that mimic legitimate cell towers. Mobile 
devices in the vicinity connect to these fake towers, allowing attackers to capture 
the International Mobile Subscriber Identity (IMSI), track users, and intercept communications.

- **Weak Encryption Algorithms:** Early GSM encryption standards, such as A5/1 and 
A5/2, are now considered weak and can be cracked with modest resources. Attackers 
can eavesdrop on calls and SMS by decrypting intercepted radio signals.

- **Man-in-the-Middle (MitM) Attacks:** By placing themselves between the mobile 
device and the legitimate network, attackers can intercept, alter, or inject communications, 
often without the user’s knowledge.

- **Signaling Exploits:** Vulnerabilities in GSM’s signaling protocols (like SS7) 
can be abused to redirect calls or SMS messages to an attacker, enabling interception 
even if the attacker is not physically near the target.

## Threat impact

- **Eavesdropping:** Attackers can listen to phone calls and read SMS messages, 
compromising user privacy and potentially exposing sensitive or confidential information.

- **Location Tracking:** By capturing IMSI and other identifiers, attackers can 
track a user’s movements in real time.

- **Data Manipulation:** In MitM scenarios, attackers can alter messages or inject 
malicious content during transmission.

- **Fraud and Identity Theft:** Intercepted communications can be used for social 
engineering, phishing, or unauthorized access to accounts (e.g., intercepting SMS-based 
two-factor authentication).

## Real-world examples

- **Commercial Surveillance Devices:** Commercially available devices can intercept 
GSM traffic, extract encryption keys, and monitor communications. These devices 
are used by law enforcement, intelligence agencies, and sometimes by criminals to 
conduct surveillance or steal information.

- **Notorious Attacks:** There have been documented cases where attackers used GSM 
interception to gain access to bank accounts by intercepting SMS-based authentication codes.

## Techniques
- T1638
- T1040
- T1589
- T1190
