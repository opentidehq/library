# Shai-Hulud Known On-Disk and Network Indicator Match

## Metadata

- **UUID**: `2fe6575d-513c-4588-999f-19c13d0fa4f9`
- **Schema**: `rule::1.0`
- **TLP**: clear

## Description
#### MDR Technical Details
Multi-platform detection rule implementing DOM signal
`678d0786-dfd7-40fb-ba90-3c368ed00342` (Known Shai-Hulud On-Disk and
Network Indicator Match). Microsoft Defender for Endpoint matches campaign
filenames, SHA-256 hashes, and package-runtime network connections in
`DeviceFileEvents` and `DeviceNetworkEvents`. Microsoft Sentinel correlates
DNS queries, proxy or firewall logs, and `ThreatIntelIndicators` for the same
campaign infrastructure and package indicators.

#### Detection Criteria
- On-disk: `router_init.js`, `setup.mjs`, `gh-token-monitor`, or published
  sample SHA-256 hashes (endpoint).
- Network: connections or DNS to `git-tanstack.com`, `*.getsession.org`, or
  `83.142.209.194` from package-runtime process trees (endpoint) or DNS,
  proxy, and threat-intel feeds (Sentinel).
- Frequency: 1 hour; severity Critical.

#### Exclusion Criteria
- None for hash and filename matches — treat as strong execution evidence.
- DNS-only matches on security-research sandboxes should be scoped to
  developer and CI network segments where possible.

## Techniques
- T1195.002
- T1547
- T1071.001
- T1567.002

## Platform configurations
<details><summary>sentinel</summary>

```sql
// Detection: Shai-Hulud known network and IOC indicator match
// DOM signal: 678d0786-dfd7-40fb-ba90-3c368ed00342
// MITRE ATT&CK: T1071.001, T1195.002
// Platform: SENTINEL
let IocDomains = dynamic([
    "git-tanstack.com", "getsession.org", "filev2.getsession.org",
    "seed1.getsession.org", "seed2.getsession.org", "seed3.getsession.org"
]);
let ExfilIp = "83.142.209.194";
let DnsMatch =
DnsEvents
| where TimeGenerated > ago(1h)
| where Name has_any (IocDomains)
| project TimeGenerated, ClientIP = ClientIP, IndicatorValue = Name,
    MatchSource = "DnsEvents", IndicatorType = "domain";
let ProxyMatch =
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DestinationIP == ExfilIp
    or DestinationHostName has_any (IocDomains)
| project TimeGenerated, ClientIP = SourceIP,
    IndicatorValue = coalesce(DestinationHostName, DestinationIP),
    MatchSource = "CommonSecurityLog", IndicatorType = "network";
let TiMatch =
ThreatIntelIndicators
| where TimeGenerated > ago(7d)
| where ExpirationDateTime > now() and Active == true
| where Description has_any ("Shai-Hulud", "mini-shai-hulud", "git-tanstack")
    or DomainName has_any (IocDomains)
    or NetworkIP == ExfilIp
| extend IndicatorValue = coalesce(DomainName, NetworkIP, Description)
| project TimeGenerated, ClientIP = "", IndicatorValue,
    MatchSource = "ThreatIntelIndicators", IndicatorType = ThreatType;
union DnsMatch, ProxyMatch, TiMatch
| order by TimeGenerated desc
```



</details>

<details><summary>defender_for_endpoint</summary>

```sql
// Detection: Shai-Hulud known on-disk and network IOC match
// DOM signal: 678d0786-dfd7-40fb-ba90-3c368ed00342
// MITRE ATT&CK: T1195.002, T1547
// Platform: DEFENDER
let PackageManagers = dynamic([
    "node", "node.exe", "npm", "npm.cmd", "pnpm", "pnpm.cmd",
    "yarn", "yarn.cmd", "npx", "corepack", "pip", "pip3",
    "python", "python3", "bun", "bun.exe"
]);
let IocDomains = dynamic([
    "git-tanstack.com", "getsession.org", "filev2.getsession.org",
    "seed1.getsession.org", "seed2.getsession.org", "seed3.getsession.org"
]);
let IocFiles = dynamic([
    "router_init.js", "setup.mjs", "router_runtime.js",
    "tanstack_runner.js", "gh-token-monitor",
    "com.user.gh-token-monitor.plist", "gh-token-monitor.service",
    "transformers.pyz"
]);
let IocHashes = dynamic([
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96",
    "2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df"
]);
let FileMatch =
DeviceFileEvents
| where FileName in~ (IocFiles) or SHA256 in (IocHashes)
| project Timestamp, DeviceId, ReportId, DeviceName,
    AccountName = InitiatingProcessAccountName, AccountSid = "",
    InitiatingProcessFileName, InitiatingProcessCommandLine = FolderPath,
    FileName, ProcessCommandLine = SHA256,
    DetectionType = "file_ioc";
let NetworkMatch =
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (IocDomains) or RemoteIP == "83.142.209.194"
| where InitiatingProcessFileName in~ (PackageManagers)
    or InitiatingProcessCommandLine has_any (IocFiles)
| project Timestamp, DeviceId, ReportId, DeviceName,
    AccountName = InitiatingProcessAccountName, AccountSid = "",
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName = RemoteUrl, ProcessCommandLine = RemoteIP,
    DetectionType = "network_ioc";
union FileMatch, NetworkMatch
```



</details>
