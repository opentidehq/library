# Shai-Hulud Unexpected GitHub Repository or Workflow Creation

## Metadata

- **UUID**: `7eb85d22-2e60-449f-b92c-8cecc28d34c6`
- **Schema**: `rule::1.0`
- **TLP**: clear

## Description
#### MDR Technical Details
Microsoft Sentinel scheduled analytic rule implementing DOM signal
`287114bd-7d58-422d-9711-f5516900b9ce` (Unexpected GitHub Repository or
Workflow Creation from Anomalous Context). Searches `GitHubAuditLog` and
`CloudAppEvents` for dead-drop repository markers, suspicious workflow
commits, and package-related audit actions.

#### Detection Criteria
- GitHub audit `Data` or CloudApp `RawEventData` contains campaign strings:
  `Shai-Hulud: Here We Go Again`, `PUSH UR T3MPRR`, or the token-wipe
  commit message.
- OR repository/workflow actions involving `router_init.js`, `setup.mjs`,
  or `.github/workflows` from GitHub application telemetry.
- Time window: 1 hour lookback with 1 hour frequency.
- Severity: High.

#### Exclusion Criteria
- Legitimate open-source forks and hobby repositories — correlate with
  endpoint install anomalies on linked CI runners before escalation.
- Dune-themed repository names alone are insufficient; require marker
  strings or malicious workflow file references.

## Techniques
- T1195.002
- T1078
- T1567.002

## Platform configurations
<details><summary>sentinel</summary>

```sql
// Detection: Shai-Hulud unexpected GitHub repository or workflow creation
// DOM signal: 287114bd-7d58-422d-9711-f5516900b9ce
// MITRE ATT&CK: T1195.002, T1078
// Platform: SENTINEL
let ShaiHuludMarkers = dynamic([
    "Shai-Hulud: Here We Go Again",
    "PUSH UR T3MPRR",
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"
]);
let MaliciousPaths = dynamic([
    "router_init.js", "setup.mjs", ".github/workflows"
]);
let GitHubAudit =
GitHubAuditLog
| where TimeGenerated > ago(1h)
| extend DataStr = tostring(Data)
| where Action has_any ("repo.", "workflows.", "packages.")
| where DataStr has_any (ShaiHuludMarkers)
    or (Action has "repo.create" and DataStr has "dune")
| project TimeGenerated, Actor, Action, Repository, DataStr,
    IPAddress = "", Source = "GitHubAuditLog";
let CloudAppGitHub =
CloudAppEvents
| where TimeGenerated > ago(1h)
| where Application has "GitHub"
| where ActionType has_any ("Create", "Publish", "Push", "Commit")
| extend RawStr = tostring(RawEventData)
| where RawStr has_any (ShaiHuludMarkers)
    or ObjectName has_any (MaliciousPaths)
| project TimeGenerated, Actor = AccountDisplayName, Action = ActionType,
    Repository = ObjectName, DataStr = RawStr,
    IPAddress, Source = "CloudAppEvents";
union GitHubAudit, CloudAppGitHub
| order by TimeGenerated desc
```



</details>
