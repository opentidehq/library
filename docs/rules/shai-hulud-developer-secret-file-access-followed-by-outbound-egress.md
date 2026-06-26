# Shai-Hulud Developer Secret-File Access Followed by Outbound Egress

## Metadata

- **UUID**: `ecd096d2-7fc5-45e3-803f-82d13f940210`
- **Schema**: `rule::1.0`
- **TLP**: clear

## Description
#### MDR Technical Details
Microsoft Defender for Endpoint custom detection implementing DOM signal
`365e23e8-0367-4adf-b18a-f1440cc66005` (Developer Secret-File Access
Followed by Outbound Network Egress). Joins `DeviceFileEvents` secret-path
reads with `DeviceNetworkEvents` outbound connections to Shai-Hulud IOC
destinations within a five-minute correlation window.

#### Detection Criteria
- File access on ≥ 2 distinct secret-marker paths (`.npmrc`, `.env`,
  `.ssh`, cloud credential stores, Vault tokens, etc.).
- Outbound connection within 5 minutes to `git-tanstack.com`,
  `*.getsession.org`, or `83.142.209.194`.
- Same initiating process ID on the device.
- Frequency: 1 hour; severity High.

#### Exclusion Criteria
- Legitimate `gh auth login` and cloud SDK tooling may access secret paths —
  require IOC destination match (not secret access alone).
- CI secret-injection agents should be excluded per deployment via
  `InitiatingProcessFileName` allowlists.

## Techniques
- T1552.001
- T1071.001
- T1567.002

## Platform configurations
<details><summary>defender_for_endpoint</summary>

```sql
// Detection: Shai-Hulud secret-file access followed by outbound egress
// DOM signal: 365e23e8-0367-4adf-b18a-f1440cc66005
// MITRE ATT&CK: T1552.001, T1071.001
// Platform: DEFENDER
let SecretMarkers = dynamic([
    ".npmrc", ".env", ".git-credentials", "id_rsa", "id_ed25519",
    ".aws", "credentials", "serviceaccount", ".vault-token", ".docker"
]);
let IocDomains = dynamic([
    "git-tanstack.com", "getsession.org", "filev2.getsession.org",
    "seed1.getsession.org", "seed2.getsession.org", "seed3.getsession.org"
]);
let CorrelationWindow = 5m;
let SecretReads =
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified") or ActionType has "Read"
| where FolderPath has_any (SecretMarkers) or FileName has_any (SecretMarkers)
| summarize SecretReadTime = min(Timestamp),
    SecretPathCount = dcount(strcat(FolderPath, FileName)),
    SecretPaths = make_set(strcat(FolderPath, "\\", FileName), 10)
    by DeviceId, InitiatingProcessId, InitiatingProcessFileName;
let SecretEgress =
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (IocDomains) or RemoteIP == "83.142.209.194"
| project EgressTime = Timestamp, DeviceId, ReportId, DeviceName,
    InitiatingProcessId, InitiatingProcessFileName,
    RemoteUrl, RemoteIP, RemotePort, SentBytes;
SecretReads
| where SecretPathCount >= 2
| join kind=inner SecretEgress on DeviceId, InitiatingProcessId
| where EgressTime between (SecretReadTime .. (SecretReadTime + CorrelationWindow))
| project Timestamp = EgressTime, DeviceId, ReportId, DeviceName,
    AccountName = "", AccountSid = "",
    InitiatingProcessFileName, InitiatingProcessCommandLine = strcat_array(SecretPaths, ";"),
    FileName = RemoteUrl, ProcessCommandLine = strcat(RemoteIP, ":", tostring(RemotePort)),
    SentBytes, SecretPathCount
```



</details>
