# Shai-Hulud Package Manager Install Spawning Suspicious Child Processes

## Metadata

- **UUID**: `bfae62bb-7ce1-46cd-a131-39803832fa9d`
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
`a3f7d796-146c-44b0-8d22-7a08daa0d963` (Package Manager Install Spawning
Unexpected Download or Scripting Child Processes). Correlates
`DeviceProcessEvents` for package-manager install trees spawning download
utilities, shells, Bun, or hidden-window PowerShell, and `DeviceFileEvents`
for campaign artefact drops (`router_init.js`, `setup.mjs`, etc.).

#### Detection Criteria
- Parent is npm, pnpm, yarn, pip, python, or node with install/ci/add/update
  in the command line.
- Child within the engine lookback is curl, wget, bash, sh, zsh, bun,
  powershell (hidden/bypass flags), or cscript/wscript.
- OR file create of known Shai-Hulud hook files outside npm cache paths.
- Frequency: 1 hour; severity High.

#### Exclusion Criteria
- Native module builds (`node-gyp`, `esbuild`) excluded by initiating process.
- Files under npm cache / temp paths excluded for artefact drops.
- Legitimate postinstall (husky, esbuild fetch) may fire — correlate with
  secret-file access or IOC signals before escalation.

## Status

- **Status**: `STAGING`
- **Severity**: `Informational`

## Detection model
- **Objective**: [Detect Shai-Hulud npm and PyPI Supply Chain Compromise Activity](Objectives/fb62e879-9e91-4c5b-aaa7-999b2b1b3897.md) (`fb62e879-9e91-4c5b-aaa7-999b2b1b3897`)

## Response

- **Alert severity**: High
### Procedure
- **Analysis**: 1. Confirm package manager parent command line references install, ci,
   add, or update.
2. Inspect child process command line for remote fetch or pipe-to-shell.
3. Search the device for `router_init.js`, `setup.mjs`, and lockfile
   entries for `@tanstack/*` compromised versions.
4. Correlate with other Shai-Hulud DOM signals on the same host.
- **Containment**: Isolate the endpoint if install-time child spawning coincides with IOC
file creation. Remove malicious packages and persistence before token
revocation.
#### Searches
- **Hunt related file and network IOC activity on the device** (defender_for_endpoint)
```text
let IocFiles = dynamic(["router_init.js", "setup.mjs", "gh-token-monitor"]);
union (
    DeviceFileEvents
    | where DeviceId == "{{DeviceId}}"
    | where FileName in~ (IocFiles)
), (
    DeviceNetworkEvents
    | where DeviceId == "{{DeviceId}}"
    | where RemoteUrl has "git-tanstack"
)
```

## Platform configurations
<details><summary>defender_for_endpoint</summary>

- **Enabled**: `True`
- **Status**: `DEVELOPMENT`
- **Alert title**: Shai-Hulud install hook spawned {{FileName}} on {{DeviceName}}

```sql
// Detection: Shai-Hulud package manager install child process anomaly
// DOM signal: a3f7d796-146c-44b0-8d22-7a08daa0d963
// MITRE ATT&CK: T1195.002, T1546.016
// Platform: DEFENDER
let PackageManagers = dynamic([
    "node", "node.exe", "npm", "npm.cmd", "pnpm", "pnpm.cmd",
    "yarn", "yarn.cmd", "npx", "corepack", "pip", "pip3",
    "python", "python3", "python.exe"
]);
let SuspiciousChildren = dynamic([
    "curl", "curl.exe", "wget", "wget.exe", "bash", "sh", "zsh",
    "bun", "bun.exe", "cscript.exe", "wscript.exe"
]);
let InstallVerbs = dynamic(["install", " ci", "add ", "update"]);
let MaliciousArtifacts = dynamic([
    "router_init.js", "setup.mjs", "router_runtime.js", "tanstack_runner.js"
]);
let ChildFromInstall =
DeviceProcessEvents
| where InitiatingProcessFileName in~ (PackageManagers)
    or FileName in~ (PackageManagers)
| where InitiatingProcessCommandLine has_any (InstallVerbs)
    or ProcessCommandLine has_any (InstallVerbs)
| where FileName in~ (SuspiciousChildren)
    or (FileName =~ "powershell.exe"
        and ProcessCommandLine has_any (
            "-w hidden", "-windowstyle hidden", "-ep bypass",
            "-executionpolicy bypass", "-EncodedCommand"))
| where not(InitiatingProcessFileName in~ ("node-gyp", "esbuild"))
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, AccountSid,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, ProcessCommandLine, DetectionPath = "child_process";
let ArtifactDrop =
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName in~ (MaliciousArtifacts)
| where not(FolderPath has_any ("\\npm\\cache\\", "/.npm/", "/tmp/npm-", "\\AppData\\Local\\npm-cache\\"))
| project Timestamp, DeviceId, ReportId, DeviceName,
    AccountName = InitiatingProcessAccountName, AccountSid = "",
    InitiatingProcessFileName, InitiatingProcessCommandLine = FolderPath,
    FileName, ProcessCommandLine = SHA256, DetectionPath = "artifact_drop";
union ChildFromInstall, ArtifactDrop
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
bfae62bb_7ce1_46cd_a131_39803832fa9d["Shai-Hulud Package Manager Install Spawning Suspicious Child Processes"]
bfae62bb_7ce1_46cd_a131_39803832fa9d -->|objective| fb62e879_9e91_4c5b_aaa7_999b2b1b3897
bfae62bb_7ce1_46cd_a131_39803832fa9d -->|threat| 59548b96_9b01_414c_badd_c0bf2ab40d9a
```
