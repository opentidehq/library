# Detect LINE VIPER ICMP Covert Channel on Network Devices

## Metadata

- **UUID**: `d8372ac1-2740-4cb2-b834-2e1622380b7b`
- **Schema**: `objective::1.0`
- **TLP**: clear

## Description
This detection objective targets the secondary LINE VIPER command
and control channel that uses crafted ICMP Echo Requests to deliver
encrypted tasking commands to the compromised Cisco ASA device, with
results returned over raw TCP connections using high-ephemeral ports.

The dual-protocol design — ICMP inbound, TCP outbound — is
deliberately asymmetric to complicate correlation. The ICMP tasking
channel is not sent to the WAN interface but is instead tunnelled
through an established VPN session to a LAN interface, evading
WAN-focused monitoring.

Detection relies on identifying statistically anomalous ICMP traffic
reaching LAN interfaces of network devices (particularly Cisco ASA)
via VPN tunnels, combined with correlation of unexpected outbound
raw TCP connections from the same device on high-ephemeral ports in
temporal proximity to the ICMP events.

### Anomalous ICMP Traffic to Cisco ASA LAN Interface via VPN
Detects unusual ICMP Echo Request traffic directed at the LAN
interface of a Cisco ASA device originating from VPN-connected
clients, consistent with LINE VIPER ICMP-based C2 tasking [1].

In observed LINE VIPER operations, ICMP tasking is not sent
to the WAN interface but tunnelled through an established VPN
session to reach the LAN interface. This is unusual as ICMP
traffic to network appliance interfaces from VPN clients is
uncommon in most environments.

Detection criteria:
- ICMP Echo Requests destined for the ASA's internal (LAN)
  interface IP addresses originating from VPN tunnel sources
- ICMP payloads exceeding typical ping sizes (>64 bytes)
  or containing high-entropy content inconsistent with standard
  ping tools
- ICMP Echo Requests from VPN client IPs not associated with
  legitimate network diagnostic activity (no prior session
  pattern, unusual time of day, single host sending repeated
  large ICMP packets)
- Absence of corresponding ICMP Echo Replies from the ASA
  (LINE VIPER may not respond via ICMP, only via raw TCP)

Tuning note: Establish a baseline of legitimate ICMP traffic
to ASA LAN interfaces from VPN clients — this is typically
near zero in production environments and thresholds should
be set accordingly.

**Methodology**: Anomaly

### Unexpected Outbound Raw TCP from Cisco ASA on High Ephemeral Ports
Detects unexpected outbound TCP connections initiated from a
Cisco ASA device to external IP addresses using high-ephemeral
source and/or destination ports, consistent with LINE VIPER
returning ICMP tasking results over raw TCP [1].

LINE VIPER responds to ICMP tasking by initiating raw TCP
connections to the attacker's infrastructure using high-
ephemeral ports (typically >32768). This is anomalous behaviour
for a Cisco ASA, which should not be initiating arbitrary
outbound TCP connections on high ephemeral ports to external
hosts that are not part of established VPN, management, or
update sessions.

Detection criteria:
- Outbound TCP SYN packets from Cisco ASA management or internal
  interface IP to external IP addresses on ports >32768
- Connection attempts from the ASA itself (not from clients
  behind the ASA) that do not correspond to known management
  protocols (SSH, HTTPS/443, SNMP, NTP, etc.)
- Connections to external IPs not in an approved list of
  management, NTP, syslog, or update server destinations
- Short-lived TCP connections with small data transfer volumes
  (task results are likely compact) following anomalous inbound
  ICMP events

Key distinction: this signal monitors traffic originating FROM
the ASA device's own IP address, not from clients NAT'd through
the ASA. This requires flow visibility on the upstream router
or switch, not just firewall logs.

**Methodology**: Behavioural

## Relations
```mermaid
flowchart TB
d8372ac1_2740_4cb2_b834_2e1622380b7b["Detect LINE VIPER ICMP Covert Channel on Network Devices"]
4d828106_7e97_4830_8e49_2454a84a0621["4d828106-7e97-4830-8e49-2454a84a0621"]
baad1929_d23a_4a58_a269_e49244a22ea6["baad1929-d23a-4a58-a269-e49244a22ea6"]
d8372ac1_2740_4cb2_b834_2e1622380b7b --> 4d828106_7e97_4830_8e49_2454a84a0621
d8372ac1_2740_4cb2_b834_2e1622380b7b --> baad1929_d23a_4a58_a269_e49244a22ea6
```
