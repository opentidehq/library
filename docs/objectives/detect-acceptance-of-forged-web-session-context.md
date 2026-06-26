# Detect acceptance of forged web session context

## Metadata

- **UUID**: `d4c509d7-f9ab-452a-a91d-4da040095414`
- **Schema**: `objective::1.0`
- **TLP**: clear

## Description
Detect cases where an application accepts caller-supplied state as an authentication or privilege
context. The detection capability focuses on evidence that fabricated cookies, headers, or request
variables change the server-side decision from unauthenticated to authenticated or from lower to
higher privilege. It intentionally abstracts away from the exact TVM wording and frames what SOC,
application security, and continuous assurance controls need to observe.

### Fabricated session value grants protected access
Alert when controlled validation shows a protected endpoint returning successful access after a
fabricated cookie, Authorization header, or request variable is supplied. Required comparison
fields include request path, method, injected state name, response status, response size or body
fingerprint, and authentication outcome for both baseline and injected-state requests. Store
state values only as masked labels or approved test artefacts.
Triage by confirming there is no corresponding server-issued session, signed token, or login
event that legitimately explains the successful response.

**Methodology**: Heuristic

### Client-side role or identity claim changes authorisation outcome
Alert when modifying a client-controlled identity, username, role, or feature flag changes the
authorisation decision for the same route and source context. Required fields include claimed
client attribute name, resolved server-side principal, route, response status, access decision,
and timestamp. Tune by allow-listing expected signed token claims and focusing on unsigned
cookies, plain-text headers, or application variables that should never control privilege.
Triage by comparing the claimed client-side identity or role against the server-side resolved
principal and expected authorisation policy for the route.

**Methodology**: Behavioural

### Session variable probing across protected routes
Alert on repeated attempts to discover accepted session variables by trying many cookie or
header names and simple values across protected routes. Useful fields include source IP, URL,
cookie/header names, response status, user-agent, and time window. Tune out legitimate browsers
by focusing on high counts of distinct state names, tooling user-agents, and repeated 401/403 to
200 response transitions without a corresponding login event.
As a starting point, investigate sources that try multiple authentication-like cookie or header
names across protected routes in a short window, especially when followed by successful access.

**Methodology**: Frequency Analysis

## Relations
```mermaid
flowchart TB
d4c509d7_f9ab_452a_a91d_4da040095414["Detect acceptance of forged web session context"]
7ff9ea94_7bf4_4df5_83f1_7d3dc0174653["7ff9ea94-7bf4-4df5-83f1-7d3dc0174653"]
9ba566b6_bfed_4059_bdb1_50bb3cac3c29["9ba566b6-bfed-4059-bdb1-50bb3cac3c29"]
9bfe87d7_c197_4893_b7e1_829ab6d1fcf5["9bfe87d7-c197-4893-b7e1-829ab6d1fcf5"]
d4c509d7_f9ab_452a_a91d_4da040095414 --> 7ff9ea94_7bf4_4df5_83f1_7d3dc0174653
d4c509d7_f9ab_452a_a91d_4da040095414 --> 9ba566b6_bfed_4059_bdb1_50bb3cac3c29
d4c509d7_f9ab_452a_a91d_4da040095414 --> 9bfe87d7_c197_4893_b7e1_829ab6d1fcf5
```
