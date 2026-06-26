# Paragon Spyware

## Metadata

- **UUID**: `e1741a76-3df1-430a-8dda-5c6bc9c3e1dd`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Paragon Spyware, also known as Graphite, is a sophisticated surveillance tool developed 
by Paragon Solutions, an Israeli company founded in 2019. This spyware is designed to infiltrate 
encrypted messaging apps such as WhatsApp, Signal, Facebook Messenger, and Gmail, allowing 
law enforcement and intelligence agencies to intercept private communications.    

## Key Features    

- **Zero-Click Exploit**: Graphite uses a "zero-click" method, meaning it can infect 
a device without any action from the target.
- **WhatsApp Vulnerability**: The spyware exploits a vulnerability in WhatsApp, 
using a malicious PDF file to gain access to the device.
- **Data Extraction**: Once installed, Graphite can extract stored files, photos, 
and monitor communications across various platforms.
- **Cloud Upload**: The extracted data is uploaded to a cloud server, leaving no 
traces on the infected device.
- **Sandbox Escape**: The spyware can escape the Android sandbox to compromise other 
apps on the targeted devices.    

## Recent Developments    

In January 2025, WhatsApp patched a zero-day vulnerability that was being exploited 
by Paragon Spyware. The company notified approximately 90 Android users from over 
20 countries who were targeted, including journalists and activists.

## Techniques
- T1430
- T1636.003
- T1189
- T1513
- T1633
- T1068
