# Detect LINE VIPER Defence Evasion on Cisco ASA

## Metadata

- **UUID**: `7c0f2788-690e-4d34-b9eb-5f76e7363ccc`
- **Schema**: `objective::1.0`
- **Version**: `1`
- **Created**: `2026-06-18`
- **Modified**: `2026-06-18`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf](https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf)

## Description
This detection objective addresses the defence evasion and anti-
forensic capabilities of the LINE VIPER implant on Cisco ASA devices,
specifically the AAA authentication bypass, syslog message
suppression, and system integrity check manipulation.

LINE VIPER operates as a memory-resident implant within the lina
binary and hooks multiple subsystems to suppress evidence of its
presence and operations. These capabilities collectively reduce the
security telemetry available from a compromised ASA device, making
detection through conventional log analysis unreliable.

Detection must therefore focus on identifying the ABSENCE of expected
telemetry (authentication logs for established connections, expected
syslog messages) as well as inconsistencies in Cisco ASA integrity
check outputs compared to out-of-band verification.

This is a high-investment objective requiring collection of Cisco
ASA syslog at high fidelity, establishment of behavioural baselines,
and integration of out-of-band integrity verification processes.

## Objective metadata

- **Priority**: Critical
- **Type**: Threat
- **Investment**: Major
- **Composition**: Independent
- **Composition rationale**: The three signals in this objective address distinct defence
evasion mechanisms and can each be deployed independently.
Together they provide complementary coverage:

1. **AAA log gap** targets the authentication bypass by detecting
   the absence of expected authentication records for established
   network connections — a signal that is difficult to suppress
   without removing the connection telemetry entirely.

2. **Syslog suppression** targets the absence of expected ASA
   system messages, using statistical baselining to detect when
   the volume or pattern of syslog output diverges from the
   normal operational profile.

3. **Integrity check manipulation** targets LINE VIPER's patching
   of Cisco ASA system integrity checks, surfacing divergence
   between on-device integrity check results and out-of-band
   verification using trusted reference images.

Each signal can independently trigger investigation of a
potentially compromised ASA device. Correlation across signals
on the same device significantly increases confidence.

## Signals
### Cisco ASA Authentication Log Gap for Established Network Connections
Detects the absence of expected Cisco ASA AAA authentication
syslog events for network connections that are otherwise visible
in traffic logs, indicating LINE VIPER's AAA bypass capability
is suppressing authentication records [1].

LINE VIPER hooks AAA processing in lina to allow actor-
controlled devices to connect without generating authentication
logs. In normal operation, all connections requiring
authentication generate syslog events (e.g., `%ASA-6-113015`,
`%ASA-6-113005`, `%ASA-6-713228` for VPN authentication).

Detection approach (negative signal / log gap):
- Establish baseline of expected authentication syslog message
  types and volumes per Cisco ASA device
- Correlate established VPN sessions or management connections
  (visible in `%ASA-6-602303` ISAKMP or NetFlow) against
  corresponding authentication syslog events
- Alert when connections are established or sustained without
  corresponding AAA authentication success or failure events
- Monitor for sustained periods (>10 minutes) of network
  activity from an external IP to the ASA without any
  associated authentication log entries

This is a statistical/absence-based signal. Tuning requires
a well-established baseline. Note that some connections (e.g.,
pre-shared key VPNs configured without AAA) may legitimately
lack authentication logs — these must be documented and
excluded.

- **Severity**: High
- **Methodology**: Anomaly
- **Effort**: 6
#### Data

- **Availability**: Partial
- **Requirements**: - Cisco ASA syslog at minimum severity level 6 (informational)
  to a centralised SIEM
- NetFlow/IPFIX or connection logs to correlate traffic with
  authentication events
- Documented baseline of legitimate non-AAA connections
- SIEM correlation rules capable of absence/gap detection
  across multiple event types

Preferred log sources:
- Cisco ASA syslog forwarded to SIEM (all severity levels)
- NetFlow from upstream infrastructure
- Cisco Identity Services Engine (ISE) RADIUS/TACACS+ logs
  as supplementary authentication record source
- **Entities**: Authentication, IP Address, Hostname, Network Connection
### Anomalous Reduction in Cisco ASA Syslog Message Volume
Detects statistical anomalies in Cisco ASA syslog output volume
or message type distribution that may indicate LINE VIPER's
syslog suppression capability is filtering specific message
categories to conceal malicious activity [1].

LINE VIPER suppresses specific syslog messages on the
compromised ASA device. This manifests as an unexpected drop
in the volume of particular syslog message types (e.g.,
authentication events, connection events, crypto events) while
the device continues to process traffic.

Detection criteria:
- Statistical baseline deviation: syslog message volume for
  specific facility/severity combinations drops below a defined
  threshold relative to observed traffic volume on the device
- Absence of expected recurring syslog message types during
  periods of known device activity (e.g., no `%ASA-6-302013`
  TCP connection events during periods with confirmed TCP flows)
- Sudden reduction in aggregate syslog event rate from an ASA
  device without a corresponding reduction in handled traffic
  or known maintenance window
- Disappearance of specific message IDs that were previously
  consistently present in the syslog stream

This signal requires a well-established baseline syslog profile
per device. Syslog gaps caused by network issues between the
ASA and syslog server must be distinguished from in-device
suppression through cross-validation with alternative telemetry.

- **Severity**: Medium
- **Methodology**: Statistical
- **Effort**: 7
#### Data

- **Availability**: Partial
- **Requirements**: - Centralised syslog collection from all Cisco ASA devices
- Historical syslog baseline per device (minimum 4 weeks)
- Statistical analysis capability in SIEM (volume trending,
  anomaly scoring)
- Supplementary traffic telemetry (NetFlow, SNMP interface
  counters) for cross-validation of device activity levels

Preferred log sources:
- Cisco ASA syslog (all facility levels forwarded to SIEM)
- SNMP interface counter polling for traffic volume baseline
- NetFlow as independent traffic volume indicator
- **Entities**: Hostname, Software
### Cisco ASA System Integrity Check Result Inconsistency
Detects divergence between Cisco ASA on-device system integrity
check results and out-of-band verification of device image
integrity, indicating LINE VIPER has patched the integrity
checking mechanism to return falsely clean results [1].

LINE VIPER patches Cisco ASA system integrity checks within
the lina binary to return results indicating the device is
uncompromised, even when malicious modifications are present
in memory or on disk. This means the standard `show
version` or Cisco's ROMMON integrity verification may report
a clean state on a compromised device.

Detection approach:
- Collect Cisco ASA integrity check results via standard
  management interfaces (`show version`, `verify /sha-512
  <image>`, Cisco Trust Anchor Technologies where available)
- Independently verify image integrity by extracting the boot
  image hash via out-of-band access (ROMMON/console) or
  comparing against Cisco Software Checker hashes for the
  specific firmware version
- Alert on any discrepancy between on-device integrity check
  output and independently computed reference hashes
- Monitor for changes in integrity check output format or
  unexpectedly clean results following known indicators of
  compromise on the device

Given that LINE VIPER targets firmware versions 9.12(4)67
and 9.14(4)24, these specific versions warrant priority
integrity verification when detected in the environment.

- **Severity**: Critical
- **Methodology**: Artifacts
- **Effort**: 5
#### Data

- **Availability**: Partial
- **Requirements**: - Cisco ASA management access for `verify` and `show version`
  command execution
- Out-of-band console or ROMMON access capability for
  independent verification
- Reference hash library for targeted Cisco ASA firmware
  versions (from Cisco CCO/Software Checker)
- Scheduled integrity check process (automated preferred)

Preferred log sources:
- Cisco ASA management plane command output (collected via
  automated scripts or Cisco DNA Center)
- Cisco PSIRT advisories and Software Checker for reference
  hashes
- ROMMON console output for independent boot image hash
- **Entities**: Hostname, Software, File Hash

## Signal MDR coverage
| Signal | Downstream MDR rules |
| --- | --- |
| Cisco ASA Authentication Log Gap for Established Network Connections | _None_ |
| Anomalous Reduction in Cisco ASA Syslog Message Volume | _None_ |
| Cisco ASA System Integrity Check Result Inconsistency | _None_ |

## Relations
```mermaid
flowchart TB
subgraph "Signal"
0114324a_80a5_46cb_a75c_6f4a2301b7e5["0114324a-80a5-46cb-a75c-6f4a2301b7e5"]
10482800_4d71_4246_93f4_6edfc4705b86["10482800-4d71-4246-93f4-6edfc4705b86"]
9666e19f_f48d_4a0b_bb3e_0efbd69e8eac["9666e19f-f48d-4a0b-bb3e-0efbd69e8eac"]
end
subgraph "Threat"
53389577_fd8d_4ce6_9852_8365ed947c17["AAA bypass for unauthorized access on network devices"]
a6f331e0_292d_4d83_87a9_46aa149555dd["RayInitiator GRUB bootkit persistence on Cisco ASA"]
b6175f16_2b61_4116_bd97_de54b02b197e["LINE VIPER shellcode loader on Cisco ASA"]
end
7c0f2788_690e_4d34_b9eb_5f76e7363ccc["Detect LINE VIPER Defence Evasion on Cisco ASA"]
7c0f2788_690e_4d34_b9eb_5f76e7363ccc -->|signal| 0114324a_80a5_46cb_a75c_6f4a2301b7e5
7c0f2788_690e_4d34_b9eb_5f76e7363ccc -->|signal| 10482800_4d71_4246_93f4_6edfc4705b86
7c0f2788_690e_4d34_b9eb_5f76e7363ccc -->|signal| 9666e19f_f48d_4a0b_bb3e_0efbd69e8eac
7c0f2788_690e_4d34_b9eb_5f76e7363ccc -->|threat| 53389577_fd8d_4ce6_9852_8365ed947c17
7c0f2788_690e_4d34_b9eb_5f76e7363ccc -->|threat| a6f331e0_292d_4d83_87a9_46aa149555dd
7c0f2788_690e_4d34_b9eb_5f76e7363ccc -->|threat| b6175f16_2b61_4116_bd97_de54b02b197e
```
