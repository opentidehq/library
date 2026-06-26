# Mobile device compromised by spyware app

## Metadata

- **UUID**: `99c78650-8e19-4756-90fb-2573242577ca`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Earlier versions of spyware apps were installed on smartphones through vulnerabilities
in commonly used apps, or involving an SMS or iMessage that provides a link to a website. 
If clicked, this link delivers malicious software that compromises the device.
It can also be installed over a wireless transceiver located near a target,
or manually if attacker can steal the phone that has been targeted.  

Since 2019, attackers have been able to install spyware on smartphones with a missed call on WhatsApp,
including delete the record of the missed call, making it impossible for the owner to know anything is amiss.
Another way is by simply sending a message to a phone that produces no notification.  

In the latest versions of spyware does not require the user to do anything. All that is required for a
successful spyware attack and installation is having a particular vulnerable app or OS installed on the device,
such as vulnerabilities in the iMessage service in iPhones which allows for infection by simply receiving a message.
This is known as a zero-click exploit.     

Once installed, spyware malware can theoretically harvest any data from the device and transmit
it back to the attacker. It can steal photos and videos, recordings, location records, communications,
web searches, passwords, call logs and social media posts.
It also has the capability to activate cameras and microphones for real-time surveillance
without the permission or knowledge of the user.

## Techniques
- T1512
- T1582
- T1513
- T1517
- T1429
- T1643
