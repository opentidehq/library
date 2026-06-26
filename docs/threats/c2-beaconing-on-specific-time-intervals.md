# C2 beaconing on specific time intervals

## Metadata

- **UUID**: `7b122bb4-fc13-438b-a052-4388c501ec59`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
C2 beaconing refers to the periodic communication between a compromised
system and a Command and Control (C2) server. The packets are sent from the
infected host to the C2 server at regular intervals, known as the `beacon
interval`, which can be down to the second to avoid suspicion. For example,
a Cobalt Strike beacon might have an average sleep of several seconds with
jitter added to disrupt the pattern. The compromised system, often is
referred as a "beacon" sends periodic signals or "beacons" to the C2 for
one of the following reasons ref [1].

- Check for new commands or updates
- Report back on its status or activities
- Receive instructions or configuration changes
- C2 beaconing on specific time intervals

To avoid detection, attackers often configure the compromised system to
beacon on specific time intervals.

### Possible C2 beaconing set-up

A threat actor can set C2 server to respond in one of the following ways.

- Fixed intervals: The beacon sends signals at fixed intervals, e.g., every
  5 minutes, 1 hour, or 24 hours.
- Randomised intervals: The beacon sends signals at randomised intervals,
  e.g., between 5-15 minutes, to make it harder to detect.
- Scheduled intervals: The beacon sends signals at specific times, e.g.,
  during business hours or when the system is most active.

### Threat actor's purposes

Attackers can set a specific timing or rules in their Command and Control
servers depends on different reasons and goals.

- Evade detection: By beaconing at regular intervals, the attacker can avoid
  detection by security systems that rely on anomaly detection or behavioral
  analysis.
- Maintain stealth: By using fixed or randomized intervals, the attacker can
  make it harder for security teams to detect the beaconing activity.
- Conserve resources: By only communicating at specific intervals, the
  attacker can conserve resources, such as bandwidth and system resources,
  on the compromised system.

## Techniques
- T1205
- T1029
