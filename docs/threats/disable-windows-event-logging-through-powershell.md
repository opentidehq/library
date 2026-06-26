# Disable Windows event logging through PowerShell

## Metadata

- **UUID**: `e5e4397f-eea4-423b-8b71-9b30d34a9d59`
- **Schema**: `threat::1.0`
- **Version**: `2`
- **Created**: `2022-01-06`
- **Modified**: `2022-01-06`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.reddit.com/r/PowerShell/comments/5fxblg/disable_event_logs_with_powershell/](https://www.reddit.com/r/PowerShell/comments/5fxblg/disable_event_logs_with_powershell/)
- **2**: [https://www.manageengine.com/network-monitoring/Eventlog_Tutorial_Part_I.html#:~:text=Types%20of%20Event%20Logs%20Each%20event%20entry%20is,Audit%20%28Security%20Log%29%20and%20Failure%20Audit%20%28Security%20Log%29.](https://www.manageengine.com/network-monitoring/Eventlog_Tutorial_Part_I.html#:~:text=Types%20of%20Event%20Logs%20Each%20event%20entry%20is,Audit%20%28Security%20Log%29%20and%20Failure%20Audit%20%28Security%20Log%29.)
- **3**: [https://social.technet.microsoft.com/Forums/officeocs/en-US/43753fb1-7055-4994-93ef-43ea828acc58/disable-windows-powershell-event-logging](https://social.technet.microsoft.com/Forums/officeocs/en-US/43753fb1-7055-4994-93ef-43ea828acc58/disable-windows-powershell-event-logging)

## Description
Threat actors can use PowerShell to disable Windows event logging.
They use this technique for example to disable diagnostic eventlogs
or some individual Windows log (for example: Application, Security
or System log).

Disabling of Application log can cause lost of the tracks for specific
application, for example: lack of visibility for authentication, time of
logon, failure events of the application or other related application
details.

Threat actors may disable Security Event log to prevent detection of
their logons on the system: number of logons, timestamp of the logon and 
with what privilege account and username they logon on the system. 

PowerShell command to clear event logs with 'Disable-EventLog' cmdlet:

Disable-EventLog -LogName "Parameter"
where the "Parameter" can be Application, Security or System

Example how to clear individual logs with -ListLog parameter:

(Get-WinEvent -ListLog *).LogName | %{[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_)}

The threat actors can specify the logname and clear an individual log with:
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("Microsoft-Windows-FailoverClustering/Diagnostic")

With the following section the Event log is disabled competely:

$wineventlog = get-winevent -ListLog "Microsoft-Windows-FailoverClustering/Diagnostic" -ComputerName hyperv-01
$wineventlog.IsEnabled = $false
$wineventlog.SaveChanges()

If the threat actors want to disable multiple event logs at once, they can
use a loop in their customly prepared PowerShell script to iterate through a
list of event log names and disable them one by one.

Example:

# Create a list of event log names to disable
$eventLogs = "Application", "System", "Security"

# Iterate through the list of event logs and disable them one by one
foreach ($eventLog in $eventLogs) {
Disable-EventLog -LogName $eventLog
}

This script will disable the "Application", "System", and "Security" event logs on the local computer.
There is an option to modify the list of event logs to include any other specific event log that the
threat actor wants to disable.

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **A threat actor has gained control over a Windows endpoint and has
privileges to disable event logging by using PowerShell commands or
scripts.

Domains: Enterprise, Public Cloud, Private Cloud
Targets: Desktop, Laptop, Server Logs, Control Server, Public-Facing Servers, Web Application Servers, Workstations, Virtual Machines
Platforms: Windows, PowerShell, AWS, Azure**

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

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1562.002` | [Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002) | Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more.(Citation: Windows Log Events) This data is used by security tools and analysts to generate detections.  The EventLog service maintains event logs from various system components and applications.(Citation: EventLog_Core_Technologies) By default, the service automatically starts when a system powers on. An audit policy, maintained by the Local Security Policy (secpol.msc), defines which system events the EventLog service logs. Security audit policy settings can be changed by running secpol.msc, then navigating to <code>Security Settings\Local Policies\Audit Policy</code> for basic audit policy settings or <code>Security Settings\Advanced Audit Policy Configuration</code> for advanced audit policy settings.(Citation: Audit_Policy_Microsoft)(Citation: Advanced_sec_audit_policy_settings) <code>auditpol.exe</code> may also be used to set audit policies.(Citation: auditpol)  Adversaries may target system-wide logging or just that of a particular application. For example, the Windows EventLog service may be disabled using the <code>Set-Service -Name EventLog -Status Stopped</code> or <code>sc config eventlog start=disabled</code> commands (followed by manually stopping the service using <code>Stop-Service  -Name EventLog</code>).(Citation: Disable_Win_Event_Logging)(Citation: disable_win_evt_logging) Additionally, the service may be disabled by modifying the “Start” value in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog</code> then restarting the system for the change to take effect.(Citation: disable_win_evt_logging)  There are several ways to disable the EventLog service via registry key modification. First, without Administrator privileges, adversaries may modify the "Start" value in the key <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security</code>, then reboot the system to disable the Security EventLog.(Citation: winser19_file_overwrite_bug_twitter) Second, with Administrator privilege, adversaries may modify the same values in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System</code> and <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application</code> to disable the entire EventLog.(Citation: disable_win_evt_logging)  Additionally, adversaries may use <code>auditpol</code> and its sub-commands in a command prompt to disable auditing or clear the audit policy. To enable or disable a specified setting or audit category, adversaries may use the <code>/success</code> or <code>/failure</code> parameters. For example, <code>auditpol /set /category:”Account Logon” /success:disable /failure:disable</code> turns off auditing for the Account Logon category.(Citation: auditpol.exe_STRONTIC)(Citation: T1562.002_redcanaryco) To clear the audit policy, adversaries may run the following lines: <code>auditpol /clear /y</code> or <code>auditpol /remove /allusers</code>.(Citation: T1562.002_redcanaryco)  By disabling Windows event logging, adversaries can operate while leaving less evidence of a compromise behind. |
