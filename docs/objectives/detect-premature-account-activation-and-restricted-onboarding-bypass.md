# Detect premature account activation and restricted onboarding bypass

## Metadata

- **UUID**: `3a73c153-abd7-40cd-86a5-4d57a42b9a44`
- **Schema**: `objective::1.0`
- **Version**: `3`
- **Created**: `2026-05-04`
- **Modified**: `2026-05-04`
- **TLP**: clear (`TLP:CLEAR`)
- **Contributors**: Hold Security Threat Research
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://owasp.org/Top10/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **2**: [https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- **3**: [https://cwe.mitre.org/data/definitions/306.html](https://cwe.mitre.org/data/definitions/306.html)

## Description
Detect account lifecycle control failures where an identity becomes usable before the intended
approval, invitation, or eligibility gate is complete. The capability is broader than a single
registration endpoint: it correlates account creation, approval state, password reset, token
issuance, and first resource access. This gives analysts a lifecycle view of onboarding bypass
rather than a simple route-hit alert.

## Objective metadata

- **Priority**: High
- **Type**: Threat
- **Investment**: Moderate
- **Composition**: Sequence
- **Composition rationale**: Correlate account lifecycle events in order: registration attempt, account object creation,
approval or invitation state, password reset, login or token issuance, and first UI/API access.
The highest-confidence condition is a newly created account receiving reset capability, session
material, or protected resource access before its approval state permits authentication.

## Signals
### Account created without required invitation or approval context
Alert when a registration endpoint creates an account without a valid invitation, approved
domain, reviewer approval, or expected onboarding source. Required fields include account ID,
registration path, source IP, tenant/environment, invitation or approval identifier, account
state, and initial role. Tune out legitimate self-service flows by comparing with a maintained
list of public registration routes and approved domains.
Triage by confirming the expected onboarding policy for the tenant or application module and
verifying whether an invitation, reviewer action, or domain eligibility check existed.

- **Severity**: High
- **Methodology**: Event Search
- **Effort**: 4
#### Data

- **Availability**: Partial
- **Requirements**: Requires application audit logs for registration attempts, account-created events, approval
records, invitation records, source IP, request path, tenant or environment, and initial role.
API gateway or web logs help identify direct backend access when the UI is hidden.
- **Entities**: Account, IP Address, URL, API Call
### Authentication material issued while account approval is pending
Alert when password reset, login, session creation, or token issuance succeeds for an account
whose lifecycle state is pending, unapproved, unverified, pending invitation validation, or
otherwise not allowed to authenticate. Required fields include account ID, lifecycle state at
decision time, reset outcome, token/session identifier, source IP, and timestamp. This is the
principal signal that a provisioned but unapproved account has become usable.
Triage by preserving the account lifecycle state at decision time and confirming whether the
password reset, login, or token service incorrectly ignored that state.

- **Severity**: Critical
- **Methodology**: Event Search
- **Effort**: 5
#### Data

- **Availability**: Partial
- **Requirements**: Requires identity, application, and token service logs with account state at decision time,
reset request outcome, token issuance outcome, session creation, source IP, user identifier,
and timestamps. Correlation must preserve historical account state, not only current state.
- **Entities**: Account, Authentication, Token, Session
### Pre-approval account accesses restricted application resources
Alert when a newly created account accesses UI pages or APIs before approval, invitation
validation, or domain eligibility checks are complete. Required fields include account ID,
account creation time, approval state, request path, response status, role, source IP, and
first-access timestamp. Prioritise access to restricted modules, internal data, administrative
paths, or endpoints that should require an established trusted account.
Triage by comparing first-access time with approval and activation timestamps, then assessing
which data or functions were exposed before the account became eligible.

- **Severity**: High
- **Methodology**: Behavioural
- **Effort**: 5
#### Data

- **Availability**: Partial
- **Requirements**: Requires account lifecycle events, authentication events, web or API access logs, account
approval state, role assignment, request path, response status, and source IP. The detection
should compare first resource access with approval or activation timestamps.
- **Entities**: Account, URL, API Call, Session

## Signal MDR coverage
| Signal | Downstream MDR rules |
| --- | --- |
| Account created without required invitation or approval context | _None_ |
| Authentication material issued while account approval is pending | _None_ |
| Pre-approval account accesses restricted application resources | _None_ |

## Relations
```mermaid
flowchart TB
subgraph "Signal"
7f6d1aae_c807_42fb_8734_4d3c6c4e9670["7f6d1aae-c807-42fb-8734-4d3c6c4e9670"]
958eeed6_43f6_43c8_8bb9_96397aab29a1["958eeed6-43f6-43c8-8bb9-96397aab29a1"]
d5906e6c_0f66_4dd6_8add_216a90b2b1f2["d5906e6c-0f66-4dd6-8add-216a90b2b1f2"]
end
subgraph "Threat"
3d7dada6_5f9d_4f67_952e_faa2ab794fde["Unauthorized account provisioning via exposed registration flow"]
end
3a73c153_abd7_40cd_86a5_4d57a42b9a44["Detect premature account activation and restricted onboarding bypass"]
3a73c153_abd7_40cd_86a5_4d57a42b9a44 -->|signal| 7f6d1aae_c807_42fb_8734_4d3c6c4e9670
3a73c153_abd7_40cd_86a5_4d57a42b9a44 -->|signal| 958eeed6_43f6_43c8_8bb9_96397aab29a1
3a73c153_abd7_40cd_86a5_4d57a42b9a44 -->|signal| d5906e6c_0f66_4dd6_8add_216a90b2b1f2
3a73c153_abd7_40cd_86a5_4d57a42b9a44 -->|threat| 3d7dada6_5f9d_4f67_952e_faa2ab794fde
```
