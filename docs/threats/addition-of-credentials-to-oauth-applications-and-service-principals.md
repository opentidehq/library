# Addition of credentials to OAuth applications and service principals

## Metadata

- **UUID**: `a8c7b250-a2d4-4a0d-82f8-23dc99c77d7b`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
The actor has been observed adding credentials (x509 keys or password
credentials) to one or more legitimate OAuth Applications or Service
Principals, usually with existing Mail.Read or Mail.ReadWrite permissions,
which grants the ability to read mail content from Exchange Online via
Microsoft Graph or Outlook REST. Examples include mail archiving
applications. Permissions are usually, but not always, AppOnly.

The actor may use their administrator privileges to grant additional
permissions to the target Application or Service Principal (e.g.  Mail.Read,
Mail.ReadWrite).

## Techniques
- T1098.001
