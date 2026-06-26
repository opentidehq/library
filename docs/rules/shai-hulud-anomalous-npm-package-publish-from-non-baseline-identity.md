# Shai-Hulud Anomalous npm Package Publish from Non-Baseline Identity

## Metadata

- **UUID**: `fae8ef2d-99e9-42f4-81ed-d40c515e8d3d`
- **Schema**: `rule::1.0`
- **TLP**: clear

## Description
#### MDR Technical Details
Microsoft Sentinel scheduled analytic rule implementing DOM signal
`9f3abdc4-7c6e-480e-b722-6d31ddd9b2d2` (Anomalous npm Package Publish
from Non-Baseline Host or Identity). Detects burst npm package publish
activity from a single GitHub actor, publish events with campaign manifest
markers in audit metadata, and supply-chain feed matches for known
compromised versions via `ThreatIntelIndicators`.

#### Detection Criteria
- Burst threshold: ≥ 3 package publish actions per actor per hour in
  `GitHubAuditLog` (worm republication pattern).
- OR audit/commit metadata references `preinstall`, `setup.mjs`,
  `optionalDependencies`, or orphan TanStack git dependency.
- OR `ThreatIntelIndicators` match on known Shai-Hulud package versions.
- Frequency: 1 hour; severity Medium.

#### Exclusion Criteria
- Monorepo bulk releases and emergency hotfix publishes — compare against
  release calendar and require manifest markers for auto-escalation.
- Maintain per-organisation critical-package publish baseline via watchlist
  when registry-watcher pipelines are available.

## Techniques
- T1195.002
- T1078
- T1485

## Platform configurations
<details><summary>sentinel</summary>

```sql
// Detection: Shai-Hulud anomalous npm package publish
// DOM signal: 9f3abdc4-7c6e-480e-b722-6d31ddd9b2d2
// MITRE ATT&CK: T1195.002, T1078
// Platform: SENTINEL
let BurstThreshold = 3;
let ManifestMarkers = dynamic([
    "preinstall", "setup.mjs", "optionalDependencies",
    "github:tanstack/router", "git+https://github.com/tanstack"
]);
let CompromisedPackages = dynamic([
    "@tanstack/react-router@1.169.5", "guardrails-ai@0.10.1",
    "mistralai@2.4.6", "@uipath/", "@mistralai/"
]);
let PublishBurst =
GitHubAuditLog
| where TimeGenerated > ago(1h)
| where Action has "packages." and Action has "publish"
| summarize PublishCount = count(),
    Packages = make_set(Repository, 20)
    by Actor, bin(TimeGenerated, 1h)
| where PublishCount >= BurstThreshold
| extend DetectionReason = strcat("publish_burst=", PublishCount),
    Repository = tostring(Packages[0]), DataStr = "";
let ManifestPublish =
GitHubAuditLog
| where TimeGenerated > ago(1h)
| where Action has_any ("packages.", "repo.", "git.")
| extend DataStr = tostring(Data)
| where DataStr has_any (ManifestMarkers)
| summarize arg_max(TimeGenerated, *) by Actor, Repository
| extend PublishCount = 1,
    DetectionReason = "manifest_marker",
    Packages = pack_array(Repository);
let TiPackageMatch =
ThreatIntelIndicators
| where TimeGenerated > ago(7d)
| where ExpirationDateTime > now() and Active == true
| where Description has_any ("Shai-Hulud", "tanstack", "mini-shai-hulud")
    or ExternalId has_any (CompromisedPackages)
| extend Actor = coalesce(tostring(AdditionalData.actor), "ti_feed"),
    Repository = coalesce(tostring(AdditionalData.package), Description),
    DetectionReason = "ti_feed_match", PublishCount = 1, DataStr = Description
| project TimeGenerated, Actor, Repository, DetectionReason, PublishCount, DataStr, Packages = pack_array(Repository);
union PublishBurst, ManifestPublish, TiPackageMatch
| project TimeGenerated, Actor, Repository, DetectionReason, PublishCount, DataStr
| order by TimeGenerated desc
```



</details>
