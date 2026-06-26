# Abusing Lolbins to Enumerate Local and Domain Accounts and Groups

## Metadata

- **UUID**: `3b1026c6-7d04-4b91-ba6f-abc68e993616`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Adversaries may attempt to enumerate the environment and list all
local system and domain accounts or groups.  
To achieve this purpose, they can use variety of tools and techniques.  
Their goal is reconnaissance, gathering of user's account information on 
the system or in the domain and further usage of accounts with higher 
privilege access.


### For Windows OS:

On Windows platforms threat actors can use the net utility or dsquery,
as examples as lolbins. Net utility commands, as examples, are executed
with additional parameters like "net localgroup", "net user" for
administrators and guest accounts. For domain users and groups net
utility commands are used with the parameter /domain.  

Examples:   

- net user /domain
- net group /domain
- net localgroup on localhost
- net user on localhost
- net localgroup "Administrators" on localhost

Executable files net.exe or net1.exe are indicators for accounts enumeration.
"Net1.exe" resides in "C:\Windows\System32" like "net.exe" and indicates process 
known as Net Command or Application Installer. These .exe files are usually related 
to run applications, batch files, and scripts that call Net utility.  

Threat actors may enumerate currently or previously connected users, or a subset
of users as for example administrative users.  

### For Linux OS (including Windows Subsystem for Linux):

Here some example of commands typically used for discovery on accounts 
and groups.

- whoami        #current user (often used in legitimate scripts)
- hostname      #show or set the system's host name
- id            #print real and effective user and group IDs
- uname         #print system information
- arp
- users
- netdiscover
- ifconfig	  #configure a network interface
- nmap
- ps            #report a snapshot of the current processes
- netstat
- uname
- issue
- groups
- tcpdump
- sudo -l
- cat /etc/shadow
- cat /etc/passwd # other command could be used to list the content of the file ex: 'less', 'more' etc.
- cat /etc/group  # Groups
- cat /etc/sudoers # File that allocate system rights to users
- last            # most recent login sessions
- ldapsearch      # Get information from LDAP server
- rpcclient       # Command-line utility used to interact with Microsoft RPC protocol. Could be used to enumerate AD
- finger          #  user information lookup command

## Techniques
- T1087.001
- T1087.002
- T1069.001
- T1069.002
