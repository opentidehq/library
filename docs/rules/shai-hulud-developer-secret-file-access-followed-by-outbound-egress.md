# Shai-Hulud Developer Secret-File Access Followed by Outbound Egress

## Metadata

- **UUID**: `ecd096d2-7fc5-45e3-803f-82d13f940210`
- **Schema**: `rule::1.0`
- **Version**: `1`
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

## Status

- **Status**: `STAGING`
- **Severity**: `Informational`

## Detection model
- **Objective**: [Detect Shai-Hulud npm and PyPI Supply Chain Compromise Activity](Objectives/fb62e879-9e91-4c5b-aaa7-999b2b1b3897.md) (`fb62e879-9e91-4c5b-aaa7-999b2b1b3897`)

## Response

- **Alert severity**: High
### Procedure
- **Analysis**: 1. Review secret paths accessed and the egress destination.
2. Trace the initiating process tree back to package-manager activity.
3. Check for worm propagation (GitHub repo creation, npm publish).
4. Rotate credentials for all accessed secret stores.
- **Containment**: Isolate the host and block egress to campaign IOC domains. Rotate all
credentials reachable from accessed secret paths before rejoining the network.
#### Searches
- **Reconstruct process tree around the alert timestamp** (defender_for_endpoint)
```text
DeviceProcessEvents
| where DeviceId == "{{DeviceId}}"
| where Timestamp between (datetime("{{Timestamp}}") - 30m .. datetime("{{Timestamp}}") + 30m)
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

## Platform configurations
<details><summary>defender_for_endpoint</summary>

- **Enabled**: `True`
- **Status**: `DEVELOPMENT`
- **Alert title**: Shai-Hulud secret access and egress on {{DeviceName}}

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

## Relations
```mermaid
flowchart TB
subgraph "Objective"
fb62e879_9e91_4c5b_aaa7_999b2b1b3897["Detect Shai-Hulud npm and PyPI Supply Chain Compromise Activity"]
end
subgraph "Threat"
59548b96_9b01_414c_badd_c0bf2ab40d9a["Shai-Hulud npm and PyPI supply chain compromise"]
end
ecd096d2_7fc5_45e3_803f_82d13f940210["Shai-Hulud Developer Secret-File Access Followed by Outbound Egress"]
ecd096d2_7fc5_45e3_803f_82d13f940210 -->|objective| fb62e879_9e91_4c5b_aaa7_999b2b1b3897
ecd096d2_7fc5_45e3_803f_82d13f940210 -->|threat| 59548b96_9b01_414c_badd_c0bf2ab40d9a
```
