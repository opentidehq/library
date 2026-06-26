# Shai-Hulud Large Encoded Payload in Outbound HTTP from Developer or Build Hosts

## Metadata

- **UUID**: `0924c742-8fdb-4ee2-95fe-91d2e5725a90`
- **Schema**: `rule::1.0`
- **Version**: `2`
- **Created**: `2026-06-16`
- **Modified**: `2026-06-22`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- **2**: [https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised)
- **3**: [https://tanstack.com/blog/npm-supply-chain-compromise-postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- **4**: [https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)

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

## Status

- **Status**: `STAGING`
- **Severity**: `Informational`

## Detection model
- **Objective**: [Detect Shai-Hulud npm and PyPI Supply Chain Compromise Activity](Objectives/fb62e879-9e91-4c5b-aaa7-999b2b1b3897.md) (`fb62e879-9e91-4c5b-aaa7-999b2b1b3897`)

## Response

- **Alert severity**: Medium
### Procedure
- **Analysis**: 1. Review bytes sent and destination host (endpoint or proxy telemetry).
2. Correlate source host with developer workstation or CI runner inventory.
3. Check for preceding bulk secret-file access signals.
4. Inspect proxy logs if available for request body encoding patterns.
- **Containment**: Block egress to campaign IOC domains and rotate credentials if
exfiltration coincides with secret-file access.

## Platform configurations
<details><summary>sentinel</summary>

- **Enabled**: `True`
- **Status**: `DEVELOPMENT`
- **Alert title**: Shai-Hulud large HTTP exfil to {{DestinationHostName}}
- **Entity mapping**: IP: Address -> SourceIP
- **Entity mapping**: URL: Url -> RequestURL

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

- **Enabled**: `True`
- **Status**: `DEVELOPMENT`
- **Alert title**: Shai-Hulud large outbound transfer to {{FileName}} from {{DeviceName}}

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

## Relations
```mermaid
flowchart TB
subgraph "Objective"
fb62e879_9e91_4c5b_aaa7_999b2b1b3897["Detect Shai-Hulud npm and PyPI Supply Chain Compromise Activity"]
end
subgraph "Threat"
59548b96_9b01_414c_badd_c0bf2ab40d9a["Shai-Hulud npm and PyPI supply chain compromise"]
end
0924c742_8fdb_4ee2_95fe_91d2e5725a90["Shai-Hulud Large Encoded Payload in Outbound HTTP from Developer or Build Hosts"]
0924c742_8fdb_4ee2_95fe_91d2e5725a90 -->|objective| fb62e879_9e91_4c5b_aaa7_999b2b1b3897
0924c742_8fdb_4ee2_95fe_91d2e5725a90 -->|threat| 59548b96_9b01_414c_badd_c0bf2ab40d9a
```
