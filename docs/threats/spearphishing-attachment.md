# Spearphishing Attachment

## Metadata

- **UUID**: `dd5d942c-bac4-4000-b9a6-ca4fef6cfb84`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Spearphishing messages are often crafted using pernicious social engineering
techniques.

In Spearphishing Attachment attacks, recipients receive emails that contain
malicious attachments. The email message entices users to open the
attachment(s) using the knowlege gained.

- displayed sender name is known by the recipient
- topic/subject is in the field of activity of the recipient
- urgency of user action (less relevant TTP for spearphishing emails)

These attachments look like valid files. In some cases, they are disguised
as MS Office, PDF files or CV files ref [5]. It could be that the attacker
manage to capture a legit document, weaponise it and send it to (new)
recipients (it has been observed that such attack can occur within tens of
minutes after the original legit document was released). In addition, there
have also been reports of TAMs sending malicious PowerPoint (PPSX) files
that exploit vulnerabilities and emails with Word document attachments that
do not require macros to be enabled in order to execute.  

Attachments may:

- contain links leading to a page for credential harvesting.
- be weaponized to install malicious software on the computer of the user or
run some actions on the device;
- or open a decoy document. This is quite frequent in attack conducted by TA
when the malware within the attachment makes some check and assess that the
was not opened on the targeted organisation. Decoy document are meant to
evade detection and avoid raising alert or recipient report to cyber
security team, such as emails with attached Word documents that do not
require enabling macros to execute.

## Common techniques to evade detection

Attackers may use several way to try to hide visually the true nature of
the file.

### Double extensions

Attackers may use double extensions to masquerade the true file type to 
trick users into opening files that might seem safe. But this TTP is quite
well addressed at front email gateway (blocking by default file with several
extension, usually also when within a compressed file). 

### Password-protected attachment

Malicious password-protected archive files are designed to deceive users
and bypass commonly deployed inspection engines to deliver malware and 
ransomware down to a user endpoint. If the Email Security tool detects a
password-protected attachment, it will scan the metadata of the file;
not the content.

### Right-to-Left Override (RLTO)

Another technique is to hide the real file extension is Right-to-Left 
Override (RLTO). Windows supports languages that are written from right 
to left using a Unicode character that causes the text that follows it 
to be displayed in reverse, this method is used to blend the real file 
extension with the file name.

## Techniques
- T1566.001
