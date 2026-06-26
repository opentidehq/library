# Shai-Hulud Large Encoded Payload in Outbound HTTP from Developer or Build Hosts

## Metadata

- **UUID**: `0924c742-8fdb-4ee2-95fe-91d2e5725a90`
- **Schema**: `rule::1.0`
- **TLP**: clear

## Description
#### MDR Technical Details
Multi-platform detection rule implementing DOM signal
`21a527de-8635-4187-87d4-c9e5f5c1badc` (Large Encoded Payload in Outbound
HTTP from Developer or Build Hosts). Microsoft Defender for Endpoint uses
`DeviceNetworkEvents` with `SentBytes` as a proxy for encoded credential
uploads; Microsoft Sentinel uses corporate web-proxy `CommonSecurityLog`
entries for large POST/PUT requests to the same Shai-Hulud IOC destinations.

#### Detection Criteria
- Outbound transfer ≥ 50 KB to `git-tanstack.com`, `filev2.getsession.org`,
  `api.github.com`, or `83.142.209.194`.
- Endpoint variant: initiating process is node, python, bun, curl, or npm family.
- Proxy variant: HTTP POST or PUT with byte-count fields where available.
- Frequency: 1 hour; severity Medium.

#### Exclusion Criteria
- Legitimate artefact uploads to internal registries — exclude corporate
  registry hostnames per deployment.
- Proxy variant requires a web-proxy connector with body-size or byte-count fields.

## Techniques
- T1567.002
- T1071.001
- T1027

## Platform configurations
<details><summary>sentinel</summary>

```sql
// Detection: Shai-Hulud large encoded outbound HTTP exfiltration (proxy)
// DOM signal: 21a527de-8635-4187-87d4-c9e5f5c1badc
// MITRE ATT&CK: T1567.002, T1071.001
// Platform: SENTINEL
let IocDomains = dynamic([
    "git-tanstack.com", "filev2.getsession.org"
]);
let MinBytes = 50000;
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where RequestMethod in ("POST", "PUT")
| where DestinationHostName has_any (IocDomains)
    or DestinationIP == "83.142.209.194"
| where ReceivedBytes >= MinBytes or SentBytes >= MinBytes
| extend RequestURL = strcat(RequestMethod, " ", DestinationHostName, DestinationURL)
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
    ReceivedBytes, SentBytes, DeviceVendor, DeviceProduct
```



</details>

<details><summary>defender_for_endpoint</summary>

```sql
// Detection: Shai-Hulud large encoded outbound HTTP exfiltration
// DOM signal: 21a527de-8635-4187-87d4-c9e5f5c1badc
// MITRE ATT&CK: T1567.002, T1071.001
// Platform: DEFENDER
let IocDomains = dynamic([
    "git-tanstack.com", "filev2.getsession.org", "api.github.com"
]);
let ExfilIp = "83.142.209.194";
let MinSentBytes = 50000;
let PackageRuntimes = dynamic([
    "node", "node.exe", "npm", "npm.cmd", "pnpm", "python", "python3",
    "bun", "bun.exe", "curl", "curl.exe"
]);
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (IocDomains) or RemoteIP == ExfilIp
| where SentBytes >= MinSentBytes
| where InitiatingProcessFileName in~ (PackageRuntimes)
| project Timestamp, DeviceId, ReportId, DeviceName,
    AccountName = InitiatingProcessAccountName, AccountSid = "",
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName = RemoteUrl, ProcessCommandLine = RemoteIP,
    SentBytes, RemotePort
```



</details>
