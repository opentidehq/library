# System reconnaissance via shell commands in supply chain attack

## Metadata

- **UUID**: `bee6e973-b0d0-4735-a26a-003f39b8c08d`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
## Executive Summary

In the Notepad++ supply chain attack investigation, Kaspersky's KEDR Expert detection 
system identified systematic reconnaissance activities performed by threat actors 
immediately after successful compromise. These activities consisted of chained Windows 
command-line utilities executed to gather comprehensive system information, with 
results redirected to text files for exfiltration or later analysis.

## Attack Pattern

The reconnaissance activity follows a consistent pattern across both identified 
infection chains, indicating a standardized post-exploitation playbook:

### Chain #1 Reconnaissance (July-August 2025)

**Working Directory**: `%appdata%\ProShow`

**Command Executed**:
```
cmd /c whoami&&tasklist > 1.txt
```

This command combination:
- Identifies the current user context (whoami)
- Enumerates all running processes (tasklist)
- Redirects output to `1.txt` in the ProShow directory

### Chain #2 Reconnaissance (September-October 2025)

**Working Directory**: `%APPDATA%\Adobe\Scripts`

The second chain demonstrates more comprehensive reconnaissance using two approaches:

#### Approach A - Single Chained Command:
```
cmd /c "whoami&&tasklist&&systeminfo&&netstat -ano" > a.txt
```

#### Approach B - Individual Commands:
```
cmd /c whoami > a.txt
cmd /c tasklist > a.txt
cmd /c systeminfo > a.txt
cmd /c netstat -ano > a.txt
```

Both approaches gather identical information but differ in execution methodology.

## Intelligence Gathered

The reconnaissance commands provide threat actors with critical information:

### 1. User Context (`whoami`)

**Purpose**: Determine privilege level and user identity

**Information Obtained**:
- Current username
- Domain membership (if applicable)
- Whether user has administrative privileges

**Attack Value**: Helps determine if privilege escalation is necessary and identifies 
high-value targets (e.g., administrators, domain accounts)

**MITRE ATT&CK**: T1033 - System Owner/User Discovery

### 2. Process Enumeration (`tasklist`)

**Purpose**: Identify running applications and security tools

**Information Obtained**:
- Active processes and their PIDs
- Memory usage per process
- Session identifiers

**Attack Value**: 
- Detect security software (EDR, antivirus, monitoring tools)
- Identify valuable applications (browsers, email clients, development tools)
- Find potential targets for process injection or credential harvesting

**MITRE ATT&CK**: T1057 - Process Discovery

### 3. System Information (`systeminfo`)

**Purpose**: Profile the target system's configuration

**Information Obtained**:
- Operating system version and build
- System architecture (x86/x64)
- Installed hotfixes and patches
- System boot time and uptime
- Domain information
- Network card configurations

**Attack Value**:
- Identify unpatched vulnerabilities for privilege escalation
- Determine system capabilities for payload compatibility
- Assess system criticality and potential value

**MITRE ATT&CK**: T1082 - System Information Discovery

### 4. Network Connections (`netstat -ano`)

**Purpose**: Map active network connections and listening services

**Information Obtained**:
- Active TCP/UDP connections with remote endpoints
- Listening ports and associated processes (via PID)
- Connection states (ESTABLISHED, LISTENING, TIME_WAIT, etc.)

**Attack Value**:
- Identify network communication patterns for stealth
- Discover additional attack surfaces (exposed services)
- Map internal network topology
- Identify potential lateral movement targets

**MITRE ATT&CK**: T1016 - System Network Configuration Discovery

## Technical Analysis

### Command Execution Characteristics

**Output Redirection Strategy**:
- Results written to text files rather than console display
- Enables offline analysis and reduces detection risk
- Facilitates data exfiltration via C2 channels

**File Naming Convention**:
- Simple filenames: `1.txt`, `a.txt`
- Non-descriptive to avoid raising suspicion
- Located in seemingly legitimate application directories

**Directory Selection**:
- `%appdata%\ProShow` - Legitimate media presentation software directory
- `%appdata%\Adobe\Scripts` - Legitimate Adobe application scripts directory
- Both locations appear innocuous and are unlikely to trigger alerts

### Execution Flow

```
Initial Access
     |
     v
cmd.exe spawned
     |
     v
Reconnaissance commands executed
     |
     v
Output redirected to text file
     |
     v
Results exfiltrated or parsed locally
     |
     v
Next stage of attack (lateral movement/data collection)
```

## Detection Opportunities

### 1. KEDR Expert Behavioral Detection

Kaspersky's KEDR Expert system successfully detected this activity through 
behavioral signatures:

- `system_owner_user_discovery`
- `using_whoami_to_check_that_current_user_is_admin`
- `system_information_discovery_win`
- `system_network_connections_discovery_via_standard_windows_utilities`

### 2. Command-Line Monitoring

**Detection Pattern**: Monitor for cmd.exe executing multiple reconnaissance 
commands in rapid succession, especially with output redirection.

**Indicators**:
```
Process: cmd.exe
Command Line: /c whoami&&tasklist&&systeminfo&&netstat -ano
Parent Process: [Suspicious executable or NSIS installer]
Output Redirection: > [filename].txt
Working Directory: %appdata%\[application]\
```

### 3. File System Monitoring

**Detection Pattern**: Creation of text files in AppData subdirectories containing 
system reconnaissance output.

**Indicators**:
- File creation: `%appdata%\ProShow\1.txt`
- File creation: `%appdata%\Adobe\Scripts\a.txt`
- File content contains output from whoami, tasklist, systeminfo, or netstat

### 4. Process Tree Analysis

**Detection Pattern**: Unusual parent-child process relationships

**Suspicious Chains**:
```
NSIS installer/updater.exe
  └─> cmd.exe
      └─> whoami.exe
      └─> tasklist.exe
      └─> systeminfo.exe
      └─> netstat.exe
```

### 5. Timeline Analysis

**Detection Pattern**: Rapid sequential execution of discovery commands

**Indicators**:
- Multiple discovery commands executed within seconds
- Executed from same parent process
- Consistent output redirection pattern

### 6. Behavioral Analytics

**Anomaly Detection**: Development workstations executing reconnaissance commands 
from non-administrative contexts, particularly when spawned by software installers 
or updaters.

**Baseline Deviation**:
- Discovery commands typically executed by administrators or IT staff
- Execution from updater processes is highly unusual
- Output redirection to application directories deviates from normal usage

## Detection Logic Examples

### Sigma Rule Concepts

```yaml
# Detect chained reconnaissance commands
detection:
  selection_cmd:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - 'whoami'
      - 'tasklist'
  selection_output:
    CommandLine|contains: '>'
  condition: selection_cmd and selection_output
```

### Sysmon Event Correlation

**Event ID 1 (Process Creation)**:
- Correlation of multiple EventID 1 events
- Same ParentProcessId
- Image paths: whoami.exe, tasklist.exe, systeminfo.exe, netstat.exe
- Short time window (< 60 seconds)
- Parent process: cmd.exe
- Grandparent process: suspicious installer/updater

### EDR Detection Logic

```
IF Process.Name == "cmd.exe" 
  AND CommandLine CONTAINS ("whoami" AND "tasklist")
  OR (CommandLine CONTAINS "systeminfo" AND "netstat")
  AND CommandLine CONTAINS ">"
  AND Parent.Name IN (suspicious_installers_list)
THEN
  ALERT "Potential Post-Compromise Reconnaissance"
  SEVERITY: Medium
  CONFIDENCE: High
```

## Mitigation Strategies

### 1. Application Whitelisting

Restrict execution of reconnaissance utilities:
- Implement AppLocker or Windows Defender Application Control (WDAC)
- Limit cmd.exe execution contexts
- Control access to whoami, systeminfo, netstat from non-administrative contexts

### 2. Command-Line Auditing

Enable comprehensive command-line logging:
- Enable Process Creation auditing (Event ID 4688)
- Enable PowerShell script block logging
- Deploy Sysmon with robust configuration for command-line capture

### 3. EDR Deployment

Deploy endpoint detection and response solutions capable of:
- Detecting behavior-based reconnaissance patterns
- Monitoring process chain relationships
- Alerting on suspicious parent-child process trees

### 4. Network Segmentation

Limit the value of reconnaissance:
- Segment networks to restrict lateral movement
- Implement zero-trust architecture
- Enforce least-privilege access

### 5. User Behavior Analytics

Monitor for anomalous activities:
- Baseline normal reconnaissance command usage per user/role
- Alert on deviations from established patterns
- Correlate with other suspicious indicators

## Threat Actor Objectives

The reconnaissance phase serves multiple attacker objectives:

1. **Situational Awareness**: Understanding the compromised environment
2. **Target Validation**: Confirming the value of the compromised host
3. **Attack Planning**: Determining next steps based on system capabilities
4. **Privilege Assessment**: Identifying need for escalation
5. **Defense Mapping**: Identifying security tools that must be evaded
6. **Network Mapping**: Planning lateral movement paths

## Community Intelligence

The specific command patterns and behaviors were documented by community member 
`soft-parsley` on the Notepad++ community forums, providing valuable intelligence 
that aided in the investigation and response to this supply chain compromise.

## Risk Assessment

**Criticality: Medium** - While reconnaissance itself doesn't cause immediate harm, 
it is a critical precursor to more damaging activities such as lateral movement, 
privilege escalation, and data exfiltration.

**Viability: Likely** - These reconnaissance techniques are standard practice across 
numerous threat actor groups and are observed frequently in post-compromise scenarios.

**Severity: Moderate Incident** - Detection of these activities indicates an active 
breach requiring immediate investigation and response. However, early detection at 
this stage provides opportunities to prevent more severe impacts.

## Response Actions

Upon detection of this reconnaissance pattern:

1. **Immediate Isolation**: Isolate the affected system from the network
2. **Forensic Collection**: Preserve reconnaissance output files for analysis
3. **Memory Dump**: Capture system memory for malware analysis
4. **Process Investigation**: Identify parent processes and investigate infection vector
5. **Network Analysis**: Review network connections for C2 communication
6. **Lateral Movement Check**: Investigate if attacker has moved beyond initial host
7. **Credential Reset**: Reset credentials for affected user accounts
8. **Patch Verification**: Ensure systems are patched and verify update sources

## Conclusion

System reconnaissance via shell commands represents a critical phase in the attack 
lifecycle where defenders have high-confidence detection opportunities. The specific 
patterns observed in the Notepad++ supply chain attack demonstrate that even 
sophisticated threat actors rely on standard Windows utilities for post-compromise 
reconnaissance, providing defenders with reliable behavioral indicators for detection 
and response.

The combination of command-line monitoring, behavioral analytics, and process tree 
analysis provides robust detection capabilities against this threat vector. Organizations 
should prioritize detection of these patterns as part of their broader supply chain 
risk management strategy.

## Techniques
- T1082
- T1016
- T1033
- T1057

## Chaining
```mermaid
flowchart LR
bee6e973_b0d0_4735_a26a_003f39b8c08d["System reconnaissance via shell commands in supply chain attack"]
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22["Notepad++ supply chain attack"]
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22
```

## Relations
```mermaid
flowchart TB
bee6e973_b0d0_4735_a26a_003f39b8c08d["System reconnaissance via shell commands in supply chain attack"]
2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c["2f7c9b4e-8d3a-4e6f-9b1c-7a5d8e2f4b6c"]
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d["Detect Notepad++ Supply Chain Compromise Activity"]
4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d["4e7b9d3f-6c2a-4e8f-9b1d-7a5c8e3f6b2d"]
6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d["6c9f3e7b-4d2a-4e8f-9b6d-3a7c5e1f8b4d"]
8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d["8d4f6b2e-9c7a-4e1f-8b3d-6a9c5e7f2b4d"]
9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d["9b6e4d8f-7c3a-4e2f-8b1d-6a9c5e7f3b4d"]
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d
bee6e973_b0d0_4735_a26a_003f39b8c08d --> 9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d
```
