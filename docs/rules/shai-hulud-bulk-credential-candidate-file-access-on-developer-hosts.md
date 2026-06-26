# Shai-Hulud Bulk Credential-Candidate File Access on Developer Hosts

## Metadata

- **UUID**: `c82cfa6b-066f-4ba3-ba07-d7eb642c8099`
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
`b49d0a94-ae13-49b3-8ad8-6c035fa3d681` (Bulk Credential-Candidate File
Access on Developer or CI Hosts). Aggregates `DeviceFileEvents` to flag
a single process tree touching ≥ 15 distinct secret-pattern paths within
a ten-minute window, filtered to non-interactive package-runtime parents.

#### Detection Criteria
- Threshold: `PathThreshold = 15` distinct credential-candidate paths per
  process per 10-minute bin (agreed with stakeholders for developer hosts).
- Initiating runtime is node, python, or bun without interactive shell parent.
- Frequency: 1 hour; severity Medium.

#### Exclusion Criteria
- Backup, DLP, and deliberate secret-scanner service accounts should be
  excluded via `InitiatingProcessFileName` allowlists per deployment.
- IDE indexing may touch multiple config files — tune threshold upward on
  developer workstations if noise persists.

## Status

- **Status**: `STAGING`
- **Severity**: `Informational`

## Detection model
- **Objective**: [Detect Shai-Hulud npm and PyPI Supply Chain Compromise Activity](Objectives/fb62e879-9e91-4c5b-aaa7-999b2b1b3897.md) (`fb62e879-9e91-4c5b-aaa7-999b2b1b3897`)

## Response

- **Alert severity**: Medium
### Procedure
- **Analysis**: 1. Review the sample paths list for breadth of secret stores accessed.
2. Confirm the initiating process is rooted in package-manager activity.
3. Hunt for outbound IOC connections on the same device.
4. Compare against known backup or security-scanning schedules.
- **Containment**: If bulk access coincides with IOC egress or install anomalies, isolate
the host and rotate all developer credentials.
#### Searches
- **Check for Shai-Hulud network IOC egress from the device** (defender_for_endpoint)
```text
DeviceNetworkEvents
| where DeviceId == "{{DeviceId}}"
| where RemoteUrl has_any ("git-tanstack", "getsession")
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

## Platform configurations
<details><summary>defender_for_endpoint</summary>

- **Enabled**: `True`
- **Status**: `DEVELOPMENT`
- **Alert title**: Shai-Hulud bulk secret-file access on {{DeviceName}}

```sql
// Detection: Shai-Hulud bulk credential-candidate file access
// DOM signal: b49d0a94-ae13-49b3-8ad8-6c035fa3d681
// MITRE ATT&CK: T1552.001
// Platform: DEFENDER
let SecretPatterns = dynamic([
    ".npmrc", ".env", "credentials", "token", "secrets",
    "id_rsa", "id_ed25519", "config.json", ".ssh", ".aws",
    ".azure", ".kube", ".vault", "serviceaccount"
]);
let PathThreshold = 15;
let PackageRuntimes = dynamic([
    "node", "node.exe", "python", "python3", "python.exe", "bun", "bun.exe"
]);
let InteractiveParents = dynamic([
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "WindowsTerminal.exe", "Terminal", "iTerm2", "bash", "zsh", "sh"
]);
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified") or ActionType has "Read"
| where FolderPath has_any (SecretPatterns) or FileName has_any (SecretPatterns)
| extend FullPath = strcat(FolderPath, "\\", FileName)
| summarize DistinctPaths = dcount(FullPath),
    SamplePaths = make_set(FullPath, 10)
    by DeviceId, InitiatingProcessId, InitiatingProcessFileName, bin(Timestamp, 10m)
| where DistinctPaths >= PathThreshold
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName in~ (PackageRuntimes)
        or FileName in~ (PackageRuntimes)
    | where InitiatingProcessFileName !in~ (InteractiveParents)
    | distinct DeviceId, InitiatingProcessId
) on DeviceId, InitiatingProcessId
| join kind=inner (
    DeviceProcessEvents
    | summarize arg_max(Timestamp, *) by DeviceId, InitiatingProcessId
    | project DeviceId, InitiatingProcessId, ReportId, DeviceName,
        AccountName, AccountSid, Timestamp
) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, AccountSid,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine = strcat("distinct_paths=", tostring(DistinctPaths)),
    FileName = "", ProcessCommandLine = strcat_array(SamplePaths, ";"),
    DistinctPaths
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
c82cfa6b_066f_4ba3_ba07_d7eb642c8099["Shai-Hulud Bulk Credential-Candidate File Access on Developer Hosts"]
c82cfa6b_066f_4ba3_ba07_d7eb642c8099 -->|objective| fb62e879_9e91_4c5b_aaa7_999b2b1b3897
c82cfa6b_066f_4ba3_ba07_d7eb642c8099 -->|threat| 59548b96_9b01_414c_badd_c0bf2ab40d9a
```
