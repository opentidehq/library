# Shai-Hulud Bulk Credential-Candidate File Access on Developer Hosts

## Metadata

- **UUID**: `c82cfa6b-066f-4ba3-ba07-d7eb642c8099`
- **Schema**: `rule::1.0`
- **TLP**: clear

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

## Techniques
- T1552.001
- T1005

## Platform configurations
<details><summary>defender_for_endpoint</summary>

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
