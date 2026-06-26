# Access token manipulation

## Metadata

- **UUID**: `2404055a-10f8-4c50-9e9b-0f26756e7838`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
### Access token:

An access token is part of the logon session of the user, and it also contains their credentials for
Windows single sign on (SSO) authentication to access local or remote network services.

When a user signs on to a machine ((irrespective of the logon type), the system generates an 
access token for them. With this access token, Windows handles the user identification,
security, and access rights on the system.

### Access token manipulation:

An attacker can manipulate access tokens to make a process appear to be initiated by a different
user account, when in reality, the request was originated by the account of the attacker.

Attackers use access tokens to escalate privileges from administrative to SYSTEM level,
allowing them to undertake malicious operations and remotely access systems in the corporate network.

### Manipulating access token by injecting malware:

- If the current logged-on user on the compromised or infected machine is a member of the administrator
  group of users or is running a process with higher privileges (e.g., by using the “runas” command),
  malware can take advantage of the privileges of the process’s access token to elevate its privileges
  on the system, allowing it to perform privileged tasks.

- Malware can enumerate the Windows processes running with higher privileges (typically SYSTEM level privileges),
  obtain the access tokens for those processes, and utilise the acquired token to launch new processes.
  As a result, the new process is launched in the context of the SYSTEM user, as represented by the token.

- Malware can also perform a token impersonation attack, in which it copies the access tokens of higher-level
  SYSTEM processes, converts them into impersonation tokens using appropriate Windows functionality, 
  and then impersonates the SYSTEM user on the infected machine, thereby elevating its privileges.

### Methods used to manipulate access tokens:  

- Theft of access tokens.
  An attacker can copy and use existing tokens from other processes to undertake malicious activities using 
  the built-in Windows API functions:
    - To make duplicate tokens of existing access tokens, utilise the DuplicateTokenEx() function.
    - The ImpersonateLoggedOnUser() function is used to run the process as another user.
    - Attackers can assign an impersonated token to a thread using the SetThreatToken() function.

- Using a stolen access token to create a new process.
  Use the CreateProcessWithTokenW() function to create a new process with a duplicated token. The attackers
  can use this function to generate tokens that implement the security context of any user they want to impersonate.

- Creating Logon sessions.
  If an attacker has the credentials for any user account, they can use the LogonUser() function to create logon 
  sessions for them remotely. They can then gain a token from the security context of the logged in user, 
  which they can give to a thread to launch a process.

## Techniques
- T1098
