# Using a Windows command prompt for credential manipulation

## Metadata

- **UUID**: `06523ed4-7881-4466-9ac5-f8417e972d13`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors may use Windows commad prompt commands to search for, access
in order to manipulate (create, modify, delete, read) user's credentials
locally or in a domain. For example, they can extract user's passwords from
Credential Manager. Windows Credential Manager is a store with all user's
saved passwords automatically during user daily work. It provides an
interface from where the credentials can be managed. To access Credential
Manager, the threat actor needs to elevate his previleges to administrator
and run the command promt console with "Run as administrator".

Cmdkey.exe is a command-prompt utility which can create, list, and delete
stored user names and passwords or credentials. It's usually located in the 
%SYSTEM% sub-folder and its usual size is around 13,850 bytes.

Example for try to gain user's details with cmdkey from Windows Credential
Manager:

cmdkey /list:testTarget

The command returns the Target(testTarget), Type(Domain Password), and the
Username(testUser).

A threat actor can also manipulate the Credential Manager database, for
example to add, modify or delete credentials from manager sections. It is
possible to add an Internet or network address, user name, password and
others.

Example for adding of entry in Credential Manager. With the command below
a threat actor can add username-password key pair for access to specific
system.

cmdkey /add:computer-name /user:user-name /pass:your-password

Example for deletion of entry in Credential Manager. A threat actor fist
execute list command to see all potential targets and select an entry for
deletion.

cmdkey /list
cmdkey /delete:target-name

Another approach to search and retrieve user's credentials with command
promt is for example with net utility. Net utility executed via the network 
is used to query for user's password. The passwords can be storred on shared
network drives or locally.

Example:

net use \\unc\path /user:username password

or 

net use \\%userdnsdomain% /user:%userdomain%\%username% *

The asterisk at the end forces to ask for password.

With net utility a threat actor can also modify already existing user name
or password or to delete the existing credentials entry. 

Examples: 

net user <username> *
<type a new password>
<retype the new password to confirm>

The command below will set the password to blank:
net user username "" 

The following command will remove the password for the user with the
specified userneme:

net user <username> /passwordreq:no

## Techniques
- T1059.003
- T1098.001
