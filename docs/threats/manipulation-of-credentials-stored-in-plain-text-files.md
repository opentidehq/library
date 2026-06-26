# Manipulation of credentials stored in plain text files

## Metadata

- **UUID**: `82dce94c-7b18-4cb9-bae0-56716b580418`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors are searching for credentials stored in plain text, usually in
an application's properties, configuration files, system memory or other
places in the system. Storing a plain text password could lead to data
leakage because, for example when the passwords are stored in clear text
in a configuration file everyone who has read access to the file can see
and steal the passwords. In most cases, even storage of a plaintext
password in a memory is considered as a security risk if the password
is not cleared immediately after it is used. Good password management
policies require that a password shouldn't be stored in a plaintext.

In some cases the user's passwords are stored in plain text when a program
application or system file crates and saves them automatically in a file
without encryption. In other cases the credentials can be stored in clear 
text by user's mistake. Threat actors are using different methods like:
password cracking, dictionary attack, social engineering and phishing
attacks, man in the middle attack, malware injections and others to steal
and manipulate credentials stored in a plain text.

One example of manipulation of credentials stored in plain text files is by
using a technique called "password cracking." This involves using a computer
program to repeatedly guess a password or its hash until the correct one is
found. If the plain text file containing the credentials is not properly
secured, an attacker could gain access to sensitive information such as
username and password combinations. Threat actors are using variety of
different tools to crack user's credentials, for example: John the Ripper,
Hashcat, Aircrack-ng, Cain and Abel, Mimikatz, custom python scripts and
others. 

Example for a code that reads a password from a properties file and uses
the password to connect to a database:

Properties prop = new Properties();
prop.load(new FileInputStream("config.properties"));
String password = prop.getProperty("password");

DriverManager.getConnection(url, usr, password);

Example for a python script scanning for files stored in a clear text:

# put your path here 
# Network SMB path you want to search 
root_dir = ("xxxxxx", "etc.")
# location where you want to put the result 
stored_dir = 'xxxxxxxxx'
# exception you want to filter
exception_path = ["snapshot"]

## Techniques
- T1552
- T1565
- T1003
- T1555.003
- T1110.002
- T1003.007
