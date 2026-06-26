# Shai-Hulud Package Manager Install Spawning Suspicious Child Processes

## Metadata

- **UUID**: `bfae62bb-7ce1-46cd-a131-39803832fa9d`
- **Schema**: `rule::1.0`
- **TLP**: clear

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

## Techniques
- T1195.002
- T1546.016
- T1059.007
- T1059.006

## Platform configurations
<details><summary>defender_for_endpoint</summary>

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
