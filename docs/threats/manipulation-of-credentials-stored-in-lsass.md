# Manipulation of credentials stored in LSASS

## Metadata

- **UUID**: `2d0beed6-6520-4114-be1f-24067628e93c`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Credentials can be stored in the Local Security Authority Subsystem
Service (LSASS) process in memory for use by the account. LSASS stores
credentials in memory on behalf of users with active Windows sessions.
LSASS can store user or system credentials in several different ways: 
Reversibly encrypted plaintext, Kerberos Tickets, NT hashes or LM
hashes. 

The threat actors can harvest these credentials with an administrative
user or SYSTEM. Administrative accounts are used by users to carry out
tasks that require special permissions, such as installing software or
renaming a computer and they need higher administrative privileges. In
the most cases the threat actors are using different tools to manipulate
the credentials in LSASS process in memory, for example: Mimikatz, Cobalt
Strike, Impacket, Metasploit, PowerSploit, Empire, Pwdump, Dumpert and
others.

Mimikatz is a tool that allows an attacker to extract clear text passwords,
hash values, and Kerberos tickets from LSASS. The tool can be used to
retrieve password information for a user account that is currently logged
into a system, or to extract the hashes of all user accounts on a system,
which can then be used to perform offline password cracking.

By manipulating LSASS, an attacker can gain access to sensitive information,
such as passwords and other credentials, and use that information to
compromise the security of a system or network.

For example, on thetarget host threat actors can use procdump:

procdump -ma lsass.exe lsass_dump

Example for a local credential dumping from LSASS memory with Mimikatz
sekurlsa:

sekurlsa::Minidump lsassdump.dmp
sekurlsa::logonPasswords

Example for process dumping memory of lsass.exe to obtain credentials.
Threat actors are using dynamic-link libraries (DLLs) like Rundll32 to
manipulate the process in LSASS memory.

rundll32 C:\windows\system32\comsvcs.dll MiniDump lsass.dmp

OR

process == rundll32.exe
&&
command_line_includes ('MiniDump')

Example for a process that access LSASS memory:

process == ('powershell.exe' || 'taskmgr.exe' || 'rundll32.exe' || 'procdump.exe' 
|| 'procexp.exe' || [other native processes that don’t normally access LSASS]) &&
cross_process_handle_to ('lsass.exe')

Threat actors can use PowerShell scripts to request process access to
lsass.exe process (an example for access to PROCESS_ALL_ACCESS – 0x1F0FFF
process):

$Handle = [Uri].Assembly.GetType('Microsoft.Win32.NativeMethods')::OpenProcess(0x1F0FFF, $False, (Get-Process lsass).Id)

If the key value pair in the registry for LSASS is changed to 1, this
is an indicator that the passwords are stored in cleartext in LSASS memory.

Example for a DWORD in the registry: 

HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/SecurityProviders/WDigest/UseLogonCredentia

## Techniques
- T1003.001
- T1218.011
- T1098
- T1003
