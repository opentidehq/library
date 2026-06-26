# Change the audit policy to disable Windows event logging

## Metadata

- **UUID**: `36694031-a3d8-474e-b0e6-f44ba94c2a22`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor may change an audit policy setting with the purpose of
disabling Event logging for specific entries. Usually the threat actor will
disable specific audit policy entries, but other scenarios can be imagined.

For example, they can change the audit policy settings manually, with
PowerShell or other scripts, through the registries or by using
Command-line interface.

Examples: 

Command-prompt (cmd) interface:

auditpol /set /category:"Account Logon" /success:disable /failure:disable

Where /success or /failure are parameters used for disabling of successful
or failed events.

auditpol /Set /Category:* /success:disable

Where the parameter /Category is used to delete only specific category, set of
categories or all of them as shown in the example with wildcard (*) character.

auditpol /clear /y
auditpol /remove /allusers

The both commands are used to clear the audit policy settings

PowerShell commands to modify Audit policies:

auditpol /get /category:*
or auditpol /list/category
PS ~> $AuditPolicyReader::GetClassicAuditPolicy()

Example for a PowerShell script that change the audit policy to audit
successful logon events on the local computer. A threat actor can modify
the $GPO and $SecuritySettingsPath variables to target a different GPO or
security setting, also can modify $AuditSettingName and $AuditSettingValue
variables to change the audit policy to a different setting or value.

Import-Module GroupPolicy
$GPO = "LocalGPO"
$SecuritySettingsPath = "Computer Configuration\Windows Settings\Security Settings"
$AuditSettingName = "Audit Logon Events"

# Set the value for the security setting.
# The values are:
# 0 = Success and Failure
# 1 = Success
# 2 = Failure

$AuditSettingValue = 1
$SecuritySettings = Get-GPRegistryValue -Name $GPO -Key $SecuritySettingsPath | Select-Object -ExpandProperty Values
$AuditSetting = $SecuritySettings | Where-Object { $_.Name -eq $AuditSettingName }
$AuditSetting.Value = $AuditSettingValue
Set-GPRegistryValue -Name $GPO -Key $SecuritySettingsPath -Value $SecuritySettings
gpupdate /force


For advanced policies, threat actors can use /r to get a csv-formatted table:

auditpol /get /category:'Account Logon' /r | ConvertFrom-Csv | 
Format-Table 'Policy Target',Subcategory,'Inclusion Setting'

Manual change: 

If the service secpol.msc is running, then a threat actor can navigate to
Security Settings\Local Policies\Audit Policy to modify the basic policy
settings or navigate to Security Settings\Advanced Audit Policy
Configuration to modify advanced policy settings.

## Techniques
- T1562.002
