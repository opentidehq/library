# Change the audit policy to disable Windows event logging

## Metadata

- **UUID**: `36694031-a3d8-474e-b0e6-f44ba94c2a22`
- **Schema**: `threat::1.0`
- **Version**: `3`
- **Created**: `2023-01-05`
- **Modified**: `2023-01-06`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://superuser.com/questions/1516725/how-to-disable-windows-10-system-log](https://superuser.com/questions/1516725/how-to-disable-windows-10-system-log)
- **2**: [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change)
- **3**: [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-policy-change](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-policy-change)
- **4**: [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set)
- **5**: [https://www.tenforums.com/performance-maintenance/170885-disable-auditing-successful-events.html](https://www.tenforums.com/performance-maintenance/170885-disable-auditing-successful-events.html)
- **6**: [https://morgantechspace.com/2013/10/auditpol-command-examples-to-change.html](https://morgantechspace.com/2013/10/auditpol-command-examples-to-change.html)
- **7**: [https://social.technet.microsoft.com/Forums/en-US/6268624d-b424-42b1-b5ff-b6261a18eade/how-to-permanently-disable-auditing-in-windows-10](https://social.technet.microsoft.com/Forums/en-US/6268624d-b424-42b1-b5ff-b6261a18eade/how-to-permanently-disable-auditing-in-windows-10)
- **8**: [https://superuser.com/questions/1059822/change-audit-policy-through-the-registry](https://superuser.com/questions/1059822/change-audit-policy-through-the-registry)
- **9**: [https://stackoverflow.com/questions/67974297/using-powershell-to-get-the-audit-policy-security-setting-value](https://stackoverflow.com/questions/67974297/using-powershell-to-get-the-audit-policy-security-setting-value)

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

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor has gained control over a Windows endpoint and has
privileges to disable event logging by making changes to the Windows audit
policy.

Domains: Enterprise, Public Cloud
Targets: Workstations, Desktop, Laptop, Input/Output Server, Public-Facing Servers, Server Logs, Web Application Servers, Control Server
Platforms: Windows**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Impairement | Incapacitation of a particular key system that will cause disruptions in day-to-day operations, and eventually service delivery. |
| Leverage | Log tampering | Log tampering or modification |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Defense Evasion | Techniques an attacker may specifically use for evading detection or avoiding other defenses. |

## Actors
| Actor | ID | Source | Description |
| --- | --- | --- | --- |
| [[Enterprise] APT29](https://attack.mitre.org/groups/G0016) | `att&ck::G0016` | ('att&ck',) | [APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)  In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020) |
| UNC2452 | `misp::2ee5ed7a-c4d0-40be-a837-20817474a15b` | ('misp',) | Reporting regarding activity related to the SolarWinds supply chain injection has grown quickly since initial disclosure on 13 December 2020. A significant amount of press reporting has focused on the identification of the actor(s) involved, victim organizations, possible campaign timeline, and potential impact. The US Government and cyber community have also provided detailed information on how the campaign was likely conducted and some of the malware used.  MITRE’s ATT&CK team — with the assistance of contributors — has been mapping techniques used by the actor group, referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, as well as SUNBURST and TEARDROP malware. |
| [[Enterprise] Sandworm Team](https://attack.mitre.org/groups/G0034) | `att&ck::G0034` | ('att&ck',) | [Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)  In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018) |
| GreyEnergy | `misp::d52ca4c4-d214-11e8-8d29-c3e7cb78acce` | ('misp',) | ESET research reveals a successor to the infamous BlackEnergy APT group targeting critical infrastructure, quite possibly in preparation for damaging attacks |
| [[Enterprise] Threat Group-3390](https://attack.mitre.org/groups/G0027) | `att&ck::G0027` | ('att&ck',) | [Threat Group-3390](https://attack.mitre.org/groups/G0027) is a Chinese threat group that has extensively used strategic Web compromises to target victims.(Citation: Dell TG-3390) The group has been active since at least 2010 and has targeted organizations in the aerospace, government, defense, technology, energy, manufacturing and gambling/betting sectors.(Citation: SecureWorks BRONZE UNION June 2017)(Citation: Securelist LuckyMouse June 2018)(Citation: Trend Micro DRBControl February 2020) |
| APT27 | `misp::834e0acd-d92a-4e38-bb14-dc4159d7cb32` | ('misp',) | A China-based actor that targets foreign embassies to collect data on government, defence, and technology sectors. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1562.002` | [Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002) | Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more.(Citation: Windows Log Events) This data is used by security tools and analysts to generate detections.  The EventLog service maintains event logs from various system components and applications.(Citation: EventLog_Core_Technologies) By default, the service automatically starts when a system powers on. An audit policy, maintained by the Local Security Policy (secpol.msc), defines which system events the EventLog service logs. Security audit policy settings can be changed by running secpol.msc, then navigating to <code>Security Settings\Local Policies\Audit Policy</code> for basic audit policy settings or <code>Security Settings\Advanced Audit Policy Configuration</code> for advanced audit policy settings.(Citation: Audit_Policy_Microsoft)(Citation: Advanced_sec_audit_policy_settings) <code>auditpol.exe</code> may also be used to set audit policies.(Citation: auditpol)  Adversaries may target system-wide logging or just that of a particular application. For example, the Windows EventLog service may be disabled using the <code>Set-Service -Name EventLog -Status Stopped</code> or <code>sc config eventlog start=disabled</code> commands (followed by manually stopping the service using <code>Stop-Service  -Name EventLog</code>).(Citation: Disable_Win_Event_Logging)(Citation: disable_win_evt_logging) Additionally, the service may be disabled by modifying the “Start” value in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog</code> then restarting the system for the change to take effect.(Citation: disable_win_evt_logging)  There are several ways to disable the EventLog service via registry key modification. First, without Administrator privileges, adversaries may modify the "Start" value in the key <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security</code>, then reboot the system to disable the Security EventLog.(Citation: winser19_file_overwrite_bug_twitter) Second, with Administrator privilege, adversaries may modify the same values in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System</code> and <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application</code> to disable the entire EventLog.(Citation: disable_win_evt_logging)  Additionally, adversaries may use <code>auditpol</code> and its sub-commands in a command prompt to disable auditing or clear the audit policy. To enable or disable a specified setting or audit category, adversaries may use the <code>/success</code> or <code>/failure</code> parameters. For example, <code>auditpol /set /category:”Account Logon” /success:disable /failure:disable</code> turns off auditing for the Account Logon category.(Citation: auditpol.exe_STRONTIC)(Citation: T1562.002_redcanaryco) To clear the audit policy, adversaries may run the following lines: <code>auditpol /clear /y</code> or <code>auditpol /remove /allusers</code>.(Citation: T1562.002_redcanaryco)  By disabling Windows event logging, adversaries can operate while leaving less evidence of a compromise behind. |
