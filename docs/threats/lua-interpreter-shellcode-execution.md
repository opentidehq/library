# Lua interpreter shellcode execution

## Metadata

- **UUID**: `bc365789-bdbb-4e78-b2ae-b097a7ccd35f`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
## Executive Summary

Lua interpreter shellcode execution is an evasion technique that leverages legitimate 
Lua scripting interpreters to execute malicious compiled Lua scripts containing 
shellcode payloads. This technique was observed in Chain #2 of the Notepad++ supply 
chain attack (September-October 2025), where threat actors used a legitimate Lua 
interpreter (script.exe) to load compiled malicious scripts (alien.ini) that 
performed in-memory shellcode injection.

## Technical Details

### Attack Flow

1. **File Deployment**: Malicious and legitimate files dropped to %APPDATA%\Adobe\Scripts\:
   - `alien.dll` (SHA1: 6444dab57d93ce987c22da66b3706d5d7fc226da) - Legitimate library
   - `lua5.1.dll` (SHA1: 2ab0758dda4e71aee6f4c8e4c0265a796518f07d) - Legitimate Lua library
   - `script.exe` (SHA1: bf996a709835c0c16cce1015e6d44fc95e08a38a) - Legitimate Lua interpreter
   - `alien.ini` (SHA1: ca4b6fe0c69472cd3d63b212eb805b7f65710d33) - MALICIOUS compiled Lua script

2. **Execution**: Command line execution:
   ```
   %APPDATA%\Adobe\Scripts\script.exe %APPDATA%\Adobe\Scripts\alien.ini
   ```

3. **Shellcode Injection**: The malicious alien.ini file:
   - Allocates executable memory in the process space
   - Places shellcode into the allocated memory
   - Launches shellcode by abusing the Windows EnumWindowStationsW API function

4. **Payload Delivery**: Shellcode acts as a Metasploit downloader to retrieve Cobalt Strike Beacon

### Malicious File Variants

Multiple variants of the alien.ini compiled Lua script were observed:
- SHA1: ca4b6fe0c69472cd3d63b212eb805b7f65710d33
- SHA1: 0d0f315fd8cf408a483f8e2dd1e69422629ed9fd
- SHA1: 2a476cfb85fbf012fdbe63a37642c11afa5cf020

### Download URLs

Cobalt Strike Beacon downloaded from:
```
https://cdncheck.it[.]com/users/admin
https://safe-dns.it[.]com/help/Get-Start
```

### Command and Control Infrastructure

C2 server URLs:
```
https://cdncheck.it[.]com/api/getInfo/v1
https://cdncheck.it[.]com/api/FileUpload/submit
https://safe-dns.it[.]com/resolve
https://safe-dns.it[.]com/dns-query
```

## Why This Technique is Effective

1. **Living off the Land**: Uses legitimate Lua interpreter (script.exe) that may be trusted
2. **File Masquerading**: Malicious payload disguised as configuration file (alien.ini)
3. **Directory Camouflage**: Files placed in Adobe Scripts directory to appear legitimate
4. **API Abuse**: Leverages legitimate Windows API (EnumWindowStationsW) for shellcode execution
5. **Memory-Only Execution**: Shellcode runs in memory, reducing disk-based artifacts
6. **Defense Evasion**: Compiled Lua scripts are less commonly analyzed than traditional executables

## Detection Opportunities

1. **Process Monitoring**:
   - Monitor for unexpected Lua interpreter (script.exe, lua.exe, lua5.1.exe) execution
   - Look for Lua interpreters spawned from unusual parent processes
   - Alert on Lua processes loading .ini or non-standard file extensions

2. **Command Line Analysis**:
   - Detect command lines executing Lua interpreters with suspicious arguments
   - Monitor for execution from %APPDATA% directories (especially Adobe\Scripts\)

3. **File System Monitoring**:
   - Watch for creation of script.exe, lua5.1.dll, alien.dll in %APPDATA% paths
   - Alert on .ini files in scripting directories
   - Monitor for file writes to %APPDATA%\Adobe\Scripts\ directory

4. **API Call Monitoring**:
   - Detect EnumWindowStationsW API calls from scripting interpreters
   - Monitor for memory allocation patterns (VirtualAlloc, VirtualAllocEx) from Lua processes
   - Alert on WriteProcessMemory calls from script interpreters

5. **Network Monitoring**:
   - Block/alert on connections to known malicious domains (cdncheck.it[.]com, safe-dns.it[.]com)
   - Monitor for unusual HTTPS/HTTP traffic from scripting processes
   - Detect Cobalt Strike Beacon network signatures

6. **Behavioral Detection**:
   - Identify Lua interpreters making network connections
   - Detect shellcode injection patterns (allocate → write → execute)
   - Alert on processes with unusual memory protection changes

## Mitigation Recommendations

1. **Application Whitelisting**:
   - Restrict execution of scripting interpreters to approved locations
   - Block execution from %APPDATA% directories where possible
   - Implement strict execution policies for .exe files in user writable directories

2. **Script Execution Controls**:
   - Monitor and control Lua interpreter usage across the environment
   - Restrict script interpreters from making network connections
   - Implement PowerShell Constrained Language Mode and similar controls for other interpreters

3. **EDR/XDR Deployment**:
   - Deploy endpoint detection solutions capable of monitoring API calls
   - Enable memory scanning to detect shellcode patterns
   - Implement behavioral analytics for script interpreter abuse

4. **Directory Monitoring**:
   - Implement strict monitoring on %APPDATA% directories
   - Alert on creation of executable content in user data directories
   - Monitor for unusual DLL loading from user-writable paths

5. **Network Security**:
   - Block known malicious infrastructure at network perimeter
   - Implement SSL/TLS inspection for HTTPS traffic analysis
   - Deploy DNS filtering to block known C2 domains

6. **Security Awareness**:
   - Train users to recognize unusual software installations
   - Educate on supply chain attack vectors
   - Implement procedures for verifying software update authenticity

## MITRE ATT&CK Mapping

- **T1059.010** - Command and Scripting Interpreter: Lua
  - Attackers used legitimate Lua interpreter (script.exe) to execute malicious compiled Lua scripts

- **T1055.001** - Process Injection: Dynamic-link Library Injection
  - Malicious Lua script allocated memory and injected shellcode into process memory space

- **T1106** - Native API
  - Abused EnumWindowStationsW Windows API function to execute shellcode
  - Likely used VirtualAlloc/VirtualAllocEx for memory allocation

## Indicators of Compromise (IOCs)

### File Hashes (SHA1)

**Legitimate files** (used in attack but not malicious):
```
6444dab57d93ce987c22da66b3706d5d7fc226da - alien.dll
2ab0758dda4e71aee6f4c8e4c0265a796518f07d - lua5.1.dll
bf996a709835c0c16cce1015e6d44fc95e08a38a - script.exe
```

**Malicious files**:
```
ca4b6fe0c69472cd3d63b212eb805b7f65710d33 - alien.ini
0d0f315fd8cf408a483f8e2dd1e69422629ed9fd - alien.ini (variant)
2a476cfb85fbf012fdbe63a37642c11afa5cf020 - alien.ini (variant)
```

### Network Indicators

**Payload Download URLs**:
```
https://cdncheck.it[.]com/users/admin
https://safe-dns.it[.]com/help/Get-Start
```

**C2 Infrastructure**:
```
https://cdncheck.it[.]com/api/getInfo/v1
https://cdncheck.it[.]com/api/FileUpload/submit
https://safe-dns.it[.]com/resolve
https://safe-dns.it[.]com/dns-query
```

**Malicious Domains**:
```
cdncheck.it[.]com
safe-dns.it[.]com
```

### File System Indicators

**File Paths**:
```
%APPDATA%\Adobe\Scripts\alien.dll
%APPDATA%\Adobe\Scripts\lua5.1.dll
%APPDATA%\Adobe\Scripts\script.exe
%APPDATA%\Adobe\Scripts\alien.ini
```

**Execution Command**:
```
%APPDATA%\Adobe\Scripts\script.exe %APPDATA%\Adobe\Scripts\alien.ini
```

## Context within Notepad++ Supply Chain Attack

This technique represents Chain #2 of the Notepad++ supply chain compromise:
- **Timeline**: September-October 2025
- **Position in Kill Chain**: Following initial access through compromised Notepad++ updates
- **Evolution**: Represented a shift from ProShow exploit (Chain #1) to interpreter-based execution
- **Parallel Variants**: Operated alongside DLL side-loading technique (Chain #3)

## Risk Assessment

**Threat Level**: HIGH

**Key Risk Factors**:
- Confirmed real-world usage in sophisticated supply chain attack
- Effective defense evasion through legitimate tool abuse
- Multiple variants indicate active development and testing
- Integration with commercial post-exploitation frameworks (Cobalt Strike)
- Targets developer and workstation environments with elevated privileges

**Target Profile**:
- Organizations using software with embedded scripting interpreters
- Development environments with Lua-based tools
- Enterprises affected by supply chain compromises
- High-value targets in government and financial sectors

## References

- Kaspersky Securelist: "Notepad++ Supply Chain Attack" (February 2026)
- Rapid7 Research: "Notepad++ Supply Chain Compromise Analysis" (February 2026)
- MITRE ATT&CK: T1059.010 (Command and Scripting Interpreter: Lua)
- MITRE ATT&CK: T1055.001 (Process Injection: Dynamic-link Library Injection)
- MITRE ATT&CK: T1106 (Native API)

## Techniques
- T1059.010
- T1055.001
- T1106

## Chaining
```mermaid
flowchart LR
bc365789_bdbb_4e78_b2ae_b097a7ccd35f["Lua interpreter shellcode execution"]
8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22["Notepad++ supply chain attack"]
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 8b7cae6f_b6cf_4414_9cdc_fe8c8ee7ee22
```

## Relations
```mermaid
flowchart TB
bc365789_bdbb_4e78_b2ae_b097a7ccd35f["Lua interpreter shellcode execution"]
2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c["2f7c9b4e-8d3a-4e6f-9b1c-7a5d8e2f4b6c"]
3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d["Detect Notepad++ Supply Chain Compromise Activity"]
4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d["4e7b9d3f-6c2a-4e8f-9b1d-7a5c8e3f6b2d"]
6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d["6c9f3e7b-4d2a-4e8f-9b6d-3a7c5e1f8b4d"]
8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d["8d4f6b2e-9c7a-4e1f-8b3d-6a9c5e7f2b4d"]
9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d["9b6e4d8f-7c3a-4e2f-8b1d-6a9c5e7f3b4d"]
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 2f7c9b4e_8d3a_4e6f_9b1c_7a5d8e2f4b6c
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 3e8b5d7f_9c2a_4f6e_8b1d_7a4c9e3f6b2d
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 4e7b9d3f_6c2a_4e8f_9b1d_7a5c8e3f6b2d
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 6c9f3e7b_4d2a_4e8f_9b6d_3a7c5e1f8b4d
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 8d4f6b2e_9c7a_4e1f_8b3d_6a9c5e7f2b4d
bc365789_bdbb_4e78_b2ae_b097a7ccd35f --> 9b6e4d8f_7c3a_4e2f_8b1d_6a9c5e7f3b4d
```
