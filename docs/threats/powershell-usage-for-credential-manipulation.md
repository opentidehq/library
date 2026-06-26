# PowerShell usage for credential manipulation

## Metadata

- **UUID**: `e3d7cb59-7aca-4c3d-b488-48c785930b6d`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors are using different methods to manipulate user's credentials.
One example of credential manipulation is by using PowerShell commands or
scripts. For example, PowerShell cmdlets or custom section of script can be
used to gather credentials from Windows Credential Manager or other
credentials stores in the system.

Example for access Windows Credential Manager credentials with PowerShell:

Install-Module CredentialManager -force
New-StoredCredential -Target $url -Username $ENV:Username -Pass <parameter>
Get-StoredCredential -Target <target>

Or threat actors can use ready PowerShell module for Credential Manager:

PS> Save-Module -Name CredentialManager -Path
PS> Install-Module -Name CredentialManager -RequiredVersion <the_version>

Example for Get-Credential cmdlet. This is a PS command which prompts a
user for his username and password, and then stores those credentials in a
$Cred variable. The stored credentials are then passed to the Get-WmiObject
cmdlet as the -Credential parameter, allowing the script to connect to the
specified remote computer using those credentials.

Example: 

$Cred = Get-Credential
Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -Credential $Cred

With a Credential parameter threat actors can pass the $credential variable
to other different commands.

Example:

PS> $credential.UserName
root

GetNetworkCredential() method is used to obtain the user's passwords.
A threat actor can append a "Password" property in the end of
GetNetworkCredential() method to display the passwords in cleartext.

Example:

PS> $credential.GetNetworkCredential()

UserName Domain
-------- ------
root

PS51> $credential.GetNetworkCredential().Password
<password_in_clear_text>

## Techniques
- T1098.001
- T1059.001
