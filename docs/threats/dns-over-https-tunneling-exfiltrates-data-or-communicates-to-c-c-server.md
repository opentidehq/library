# DNS over HTTPS tunneling exfiltrates data or communicates to C&C server

## Metadata

- **UUID**: `901dd804-00cc-4034-85aa-3d10e257c16c`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
DNS over HTTPS (DoH) tunneling is a technique used by threat actors
to exfiltrate data or communicate to a Command and Control (C&C)
server. The data exchange and transfer between the victim and the
attacker's server can include - data exfiltration (stolen data) as
confidential documents or files, PIIs, financial data or intellectual
property. The data flow can be also an administrative traffic like
covert C&C communication, for example - chat or messaging traffic,
file (malicious payload) transfers, system control, manipulation
instructions and other possible signaling or instructions transfer.

DoH is a protocol that encrypts DNS requests and responses, making
it more difficult for third parties to intercept and manipulate DNS
traffic. However, threat actors have found a way to exploit this
protocol for malicious purposes ref [1].      

In a DoH tunneling attack, the threat actor uses the DoH protocol
to encapsulate malicious data, such as stolen credentials, sensitive
information, or malware, within DNS requests. The encrypted DNS requests
are then sent to a C&C server, which can be hosted on a compromised domain
or a domain controlled by the threat actor ref [2].    

A threat actor can use some of the following initial access techniques
or methods to perform DNS over HTTPS tunneling:   

- Compromises a device: Gains access to a victim's device, either through
phishing, exploiting vulnerabilities, or using malware.
- Installs malware: Installs malware on the compromised device, which can
be designed to collect sensitive information, such as login credentials
or personal data.
- Configures DoH: Configures the device to use DoH, either by modifying
the device's DNS settings or by installing a malicious DoH client.
- Encapsulates data: Encapsulates the stolen data within DNS requests,
using techniques such as:
- Data encoding: Encoding the data using techniques like Base64 or
hexadecimal encoding.
- Data fragmentation: Breaking the data into smaller fragments and
sending them across multiple DNS requests.
- Sends DNS requests: Sends the encrypted DNS requests to the C&C
server, which can be hosted on a compromised domain or a domain
controlled by the threat actor.
- Exfiltrates data: The C&C server receives the DNS requests, extracts
the encapsulated data, and stores or forwards it to the threat actor.

## Techniques
- T1572
- T1036
- T1041
- T1190
- T1566
