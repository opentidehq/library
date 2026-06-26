# Password hash cracking on Windows

## Metadata

- **UUID**: `35c76d6c-2ac7-486e-b0b7-b56f6b110bec`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors often extract valid credentials from target systems. When
these credentials are in a hashed format, threat actors may use different
methods to crack and obtain the credentials in clear text. When this
information cannot be directly leveraged for higher privileges (like with
pass-the-hash, overpass-the-hash), it is required to crack it. Some methods
that threat actors use include: brute force, dictionary attack, or sub-set
of the dictionary attack named rainbow tables. Threat actors can use
a variety of tools to crack password hashes. For example,
Mimikatz, Hashcat, CrackStation, Password Cracker, Brutus Password Cracker,
Aircrack, THC Hydra, RainbowCrack, Cain and Abel, Medusa, John The Ripper,
ophCrack, WFuzz, L0phtCrack, OphCrack and others.

The threat actors can crack the password hashes, for example with JTR or
Hashcat cracking tools that use text files to match and crack the hashes. 
(an example for a text file could be: rockyou.txt)

gunzip /usr/share/wordlist/file.txt
john hash.txt /usr/share/wordlists/file.txt — format=nt

hashcat -m 1000 hash.txt /usr/share/wordlists/file.txt

An example of how to use Hashcat for a dictionary attack:

hashcat --attack-mode 0 --hash-type $number $hashes_file $wordlist_file

OR 

hashcat --loopback --attack-mode 0 --rules-file $rules_file --hash-type $number $hashes_file $wordlist_file

Example for Hashcat tool which can bruteforce any password from 4 to 8
characters long:

hashcat --attack-mode 3 --increment --increment-min 4 --increment-max 8 --hash-type $number $hashes_file "file"

Hashcat can also be started with custom charsets:

hashcat --attack-mode 3 --custom-charset1 "?u" --custom-charset2 "?l?u?d" --custom-charset3 "?d" --hash-type $number $hashes_file "file"

## Techniques
- T1110.002
