# Pass the ticket using Kerberos ticket

## Metadata

- **UUID**: `03cc9593-e7cf-484b-ae9c-684bf6f7199f`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Pass-the-Ticket using Kerberos tickets is an advanced method wherein threat 
actors illicitly extract and exploit Kerberos tickets to gain unauthorized 
access within a network. In the Kerberos authentication process, a Ticket 
Granting Ticket (TGT) is issued to users upon login. Adversaries involves 
the extraction of these Kerberos tickets through various means, such as 
leveraging vulnerabilities, utilizing tools like Mimikatz, or exploiting 
system weaknesses.   

Subsequently, adversaries misuse the acquired tickets to authenticate
themselves on other network systems without the need for the user's
password, allowing lateral movement and potential access to sensitive
information. Commonly employed tools, like Mimikatz and Rubeus,
facilitate these malicious activities.  

There are several types of possible TGT (ticket granting ticket)
authentication methods, for example:   

1. Credential theft technique permitting lateral movement, escalating
privileges, and gaining access to sensitive resources (TGT)  

2. Silver Ticket: Compromising Service Accounts with Kerberos Silver
Tickets (forged TGS for specific Services); The Silver ticket attack
is based on crafting a valid TGS for a service once the NTLM hash
of a user account is owned. In this case, the NTLM hash of a computer
account (which is kind of a user account in AD) is owned. Hence, it is
possible to craft a ticket in order to get into that machine with
administrator privileges through the SMB service. (ref [3])  

3. Golden Ticket: (forged TGTs) 
The Golden ticket technique is similar to the Silver ticket one,
but in this case a TGT is crafted by using the NTLM hash of the krbtgt
AD account. The advantage of forging a TGT instead of TGS is being able
to access any service (or machine) in the domain. (ref [3])    

### Tools

To carry out these attacks, adversaries use various types of tools,
such as:    

#### Mimikatz  

Commands:  

sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords

#### Rubeus  

Commands:  

\Rubeus.exe /ticket:base64blob
\Rubeus.exe ptt /ticket:BASE64BLOBHERE

#### Procdump  

Commands:  

procdump -ma lsass.exe lsass_dump  

The klist command that permit to see the Kerberos Tickets are the following:  

- Syntax: klist [-lh <logonID.highpart>] [-li <logonID.lowpart>] tickets | tgt | purge | sessions | kcd_cache | get | add_bind | query_bind | purge_bind
      * The syntax is related to Kerberos ticket management and credential cache management.

- Parameters:
    * -lh: Denotes the high part of the user's locally unique identifier (LUID), expressed in 
    hexadecimal. If neither -lh nor -li are present, the command defaults to the LUID of the 
    user who is currently signed in.
    * -li: Denotes the low part of the user's locally unique identifier (LUID), expressed in hexadecimal. 
    If neither -lh nor -li are present, the command defaults to the LUID of the user who is currently signed in.
    * tickets: Lists the currently cached ticket-granting-tickets (TGTs), and service tickets of the specified 
    logon session. This is the default option.
    * tgt: Displays the initial Kerberos TGT.
    * purge: Allows you to delete all the tickets of the specified logon session.
    * sessions: Displays a list of logon sessions on this computer.
    * kcd_cache: Displays the Kerberos constrained delegation cache information.
    * get: Allows you to request a ticket to the target computer specified by the service principal name (SPN).
    * add_bind: Allows you to specify a preferred domain controller for Kerberos authentication.
    * query_bind: Displays a list of cached preferred domain controllers for each domain that Kerberos has contacted.
    * purge_bind: Removes the cached preferred domain controllers for the domains specified.
    * kdcoptions: Displays the Key Distribution Center (KDC) options specified in RFC 4120.

## Techniques
- T1550.003
