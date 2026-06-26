# Detect Abuse of Valid Azure Credentials

## Metadata

- **UUID**: `f4a8b3c2-7e5d-4f1a-bc8e-9d2a6e7c8f0b`
- **Schema**: `objective::1.0`
- **Version**: `1`
- **Created**: `2025-10-15`
- **Modified**: `2025-10-15`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://cthfm-azure.gitbook.io/azure/mitre-att-and-ck/azure-mitre-frameworks/identity-provider-matrix-entra-id/initial-access-ta0001](https://cthfm-azure.gitbook.io/azure/mitre-att-and-ck/azure-mitre-frameworks/identity-provider-matrix-entra-id/initial-access-ta0001)
- **2**: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)
- **3**: [https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- **4**: [https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-stages-of-a-cloud-identity-compromise/](https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-stages-of-a-cloud-identity-compromise/)

## Description
Detect when adversaries abuse valid Azure AD/Entra ID credentials to gain 
unauthorized access to cloud resources. This detection objective focuses on 
identifying anomalous authentication patterns, suspicious access behaviors, 
and privilege abuse that indicate compromised credentials are being used 
for malicious purposes.

Attackers obtain credentials through various means (phishing, password spraying, 
credential leaks) and use them to authenticate legitimately to Azure services, 
making detection challenging as the authentication itself appears valid. This 
objective aims to identify the contextual anomalies and behavioral indicators 
that differentiate legitimate use from credential abuse.

Key focus areas include:
- Anomalous sign-in patterns (location, device, time, velocity)
- Privilege escalation attempts post-authentication
- Unusual resource access patterns
- Service principal and application credential abuse
- Cross-tenant authentication anomalies

## Objective metadata

- **Priority**: Critical
- **Type**: Threat
- **Investment**: Moderate
- **Composition**: Risk
- **Composition rationale**: This detection objective employs a layered correlation strategy combining 
multiple independent signals. Each signal can detect specific aspects of 
credential abuse, but when correlated, they provide high-fidelity detection 
of sophisticated attacks. The signals should be evaluated both independently 
(for high-severity individual alerts) and in combination (for attack chain 
detection). A scoring model that aggregates risk from multiple signals 
provides the most effective detection posture.

## Signals
### Anomalous Azure AD Sign-In Patterns
Detects authentication activities to Azure AD/Entra ID that deviate from 
established baseline patterns for user accounts. This includes monitoring 
for impossible travel scenarios, sign-ins from unusual geographic locations, 
unfamiliar devices, anonymous IP addresses, or suspicious ISPs.

Key detection indicators:
- Sign-in from a geographic location where the user has never authenticated before
- Impossible travel: authentication from two distant locations within an 
  unrealistic timeframe
- Authentication from TOR exit nodes, VPN services, or anonymizing proxies
- Sign-in from a device that doesn't match the user's typical device profile
- Authentication outside normal business hours for privileged accounts
- Multiple failed authentication attempts followed by a successful login
- Sign-ins with legacy authentication protocols (bypassing MFA)

Particular attention should be paid to privileged accounts (Global Administrators, 
Security Administrators, Application Administrators) as these represent high-value 
targets for attackers.

- **Severity**: High
- **Methodology**: Anomaly
- **Effort**: 3
#### Data

- **Availability**: Complete
- **Requirements**: Requires Azure AD Sign-In Logs with full diagnostic settings enabled, 
including location data, device information, authentication method details, 
and risk detection signals. Microsoft Entra ID Protection should be enabled 
to leverage built-in risk detection capabilities. Logs should include:
- Azure AD Sign-in logs (interactive and non-interactive)
- Azure AD Audit logs
- Entra ID Protection risk detections
- Conditional Access policy evaluation results

Baseline profiling of user authentication patterns over at least 30 days 
is required for effective anomaly detection. Integration with IP reputation 
services and geolocation databases enhances detection accuracy.
- **Entities**: Account, IP Address, Geolocation, Device Type, Authentication
#### Examples

1. Microsoft Sentinel detection rule that identifies sign-ins from new locations 
combined with impossible travel scenarios. Uses geo-IP lookup and temporal 
analysis to detect when the same user authenticates from two distant locations 
within an unrealistic timeframe.
   - **Link**: [https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SigninLogs/SigninAttemptsByIPviaDisabledAccounts.yaml](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SigninLogs/SigninAttemptsByIPviaDisabledAccounts.yaml)
```KQL
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend LocationDetails = parse_json(LocationDetails)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country), StartTime = min(TimeGenerated), 
            EndTime = max(TimeGenerated) by UserPrincipalName
| where array_length(Countries) > 1
```


2. Detection logic for identifying Azure AD sign-ins from anonymous IP addresses,
TOR exit nodes, or known proxy services. Correlates with Azure AD Identity 
Protection risk detections to identify high-risk authentication attempts.
   - **Link**: [https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
```KQL
let anonymousIPs = externaldata(IPAddress:string)[@"https://feeds.example.com/tor-exit-nodes.txt"];
SigninLogs
| where IPAddress in (anonymousIPs)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```


3. Sigma rule for detecting Azure AD authentications from unfamiliar locations,
with special attention to privileged accounts. Can be converted to multiple 
SIEM platforms.
   - **Link**: [https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_ad_sign_in_from_risky_ip.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_ad_sign_in_from_risky_ip.yml)
### Service Principal Credential Abuse
Detects suspicious activities involving Azure service principal credentials 
(client secrets, certificates). Service principals are non-human identities 
that applications use to authenticate, making them prime targets for attackers 
seeking persistent, stealthy access to Azure resources.

Detection focuses on:
- Service principal authentication from unexpected IP addresses or geographic locations
- Service principal used to access resources outside its typical scope
- Rapid enumeration of resources or permissions by a service principal
- Service principal credentials used after being added to an existing application
- Authentication using service principal secrets that were recently created or modified
- Service principal accessing multiple subscriptions or tenants (if not expected)
- High volume of API calls from a service principal in a short time period
- Service principal making privileged changes (role assignments, policy modifications)

Attackers who compromise service principal credentials can maintain long-term 
access while evading user-focused security controls like MFA. These credentials 
are often stored in code repositories, configuration files, or automation scripts 
where they can be harvested.

- **Severity**: High
- **Methodology**: Pattern Matching
- **Effort**: 5
#### Data

- **Availability**: Complete
- **Requirements**: Requires comprehensive Azure Activity Logs and Azure AD Audit Logs with 
focus on service principal operations. Monitoring should include:
- Azure AD Service Principal sign-in logs
- Azure Activity Logs for resource access by service principals
- Azure AD Audit logs for credential modifications (secret/certificate additions)
- Microsoft Graph API activity logs
- Azure Resource Manager (ARM) operation logs

Baseline profiling of service principal behavior patterns is essential, 
including typical resources accessed, API call patterns, and geographic 
origins of requests. Application configuration management systems (e.g., 
Azure Key Vault access logs) should also be monitored to detect credential 
harvesting attempts.
- **Entities**: Account, IP Address, Resource, API Call
### Privilege Escalation After Initial Access
Detects attempts to escalate privileges within Azure following successful 
authentication with valid credentials. This signal identifies when an attacker, 
after gaining initial access with compromised credentials, attempts to expand 
their privileges through role assignments, PIM activations, or exploitation 
of misconfigured permissions.

Key detection patterns:
- User account assigned to a privileged role (Global Admin, Security Admin, etc.) 
  shortly after a suspicious sign-in event
- Activation of Privileged Identity Management (PIM) roles from unusual locations 
  or devices
- User granted permissions to sensitive resources (Key Vaults, Storage Accounts) 
  that they've never accessed before
- Addition of credentials to existing applications or service principals
- Changes to Conditional Access policies that weaken security controls
- Modification of MFA settings for privileged accounts
- Creation of new service principals or applications with elevated permissions
- Assignment of directory roles that allow further privilege escalation

Temporal correlation is critical: privilege changes occurring within minutes 
to hours of anomalous authentication events represent high-confidence indicators 
of compromise. Attackers often move quickly to escalate privileges before 
defenders can respond to initial access alerts.

- **Severity**: Critical
- **Methodology**: Behavioural
- **Effort**: 6
#### Data

- **Availability**: Complete
- **Requirements**: Requires Azure AD Audit Logs with detailed role assignment and permission 
change tracking. Monitoring dependencies include:
- Azure AD Audit logs (role assignments, permission grants, PIM activations)
- Azure AD Sign-in logs (for temporal correlation with authentication events)
- Azure AD PIM logs (privileged role activation history)
- Microsoft Graph API audit logs (application permission modifications)
- Azure Activity Logs (RBAC role assignments at subscription/resource level)
- Conditional Access policy change logs

Requires correlation engine capable of linking sign-in events with subsequent 
privilege escalation activities within defined time windows (typically 1-24 hours). 
Baseline understanding of legitimate privilege escalation patterns (e.g., 
on-call procedures, scheduled administrative tasks) is necessary to reduce 
false positives.
- **Entities**: Account, Permissions, Authentication, API Call
#### Examples

1. KQL detection that correlates risky sign-in events from AAD Sign-in Logs 
with subsequent privilege escalation activities in Azure AD Audit Logs. 
Identifies when users are granted Global Administrator or other privileged 
roles within 4 hours of a suspicious authentication event.
   - **Link**: [https://github.com/Azure/Azure-Sentinel/tree/master/Detections/MultipleDataSources](https://github.com/Azure/Azure-Sentinel/tree/master/Detections/MultipleDataSources)
```KQL
let suspiciousSignins = SigninLogs
| where TimeGenerated > ago(4h)
| where RiskLevelDuringSignIn == "high" or RiskLevelAggregated == "high"
| project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, RiskDetail;
AuditLogs
| where TimeGenerated > ago(4h)
| where OperationName in ("Add member to role", "Add eligible member to role")
| where TargetResources has "Global Administrator"
| join kind=inner (suspiciousSignins) on UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + 4h))
| project TimeGenerated, UserPrincipalName, OperationName, IPAddress, RiskDetail
```


2. Detection rule for identifying PIM (Privileged Identity Management) role 
activations that occur from unusual locations or follow suspicious sign-in 
patterns. Monitors for emergency access account privilege elevations.
   - **Link**: [https://learn.microsoft.com/en-us/azure/sentinel/hunting](https://learn.microsoft.com/en-us/azure/sentinel/hunting)
```KQL
AuditLogs
| where OperationName == "Add eligible member to role" or OperationName == "Activate role"
| extend RoleDefinition = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where RoleDefinition has_any ("Global Administrator", "Security Administrator", "Privileged Role Administrator")
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | extend GeoIP = geo_info_from_ip_address(IPAddress)
    ) on $left.InitiatedBy == $right.UserPrincipalName
| where isnotempty(GeoIP)
```


### Suspicious Resource Enumeration and Access Patterns
Detects unusual patterns of resource enumeration and access that indicate 
an attacker is exploring the Azure environment to identify high-value targets 
after gaining access with valid credentials. This includes broad reconnaissance 
activities across subscriptions, resource groups, and sensitive assets.

Detection indicators:
- Rapid succession of read operations across multiple Azure resource types 
  (VMs, storage accounts, databases, key vaults) within a short timeframe
- User accessing resources they have never accessed historically
- Enumeration of all subscriptions, resource groups, or management groups 
  accessible to the compromised account
- PowerShell or Azure CLI commands used for systematic resource discovery 
  (Get-AzResource, az resource list, etc.)
- Microsoft Graph API queries to enumerate users, groups, applications, 
  service principals, or role assignments
- Access to sensitive resources (Key Vault secrets, storage account keys, 
  database connection strings) following initial authentication
- Cross-subscription resource access patterns that deviate from normal behavior
- Failed access attempts to resources followed by successful permission modifications

Attackers performing post-compromise reconnaissance typically exhibit scanning 
behaviors distinct from normal administrative activities: broader scope, higher 
velocity, and less targeted access patterns. Correlation with earlier authentication 
anomalies significantly increases detection confidence.

- **Severity**: Medium
- **Methodology**: Anomaly
- **Effort**: 7
#### Data

- **Availability**: Complete
- **Requirements**: Requires comprehensive Azure Activity Logs covering all resource operations, 
with particular focus on read operations and access patterns. Data requirements include:
- Azure Activity Logs (all read operations across subscriptions)
- Azure Resource Manager (ARM) operation logs
- Microsoft Graph API audit logs (for directory object enumeration)
- Azure Key Vault access logs (secret/key/certificate access)
- Azure Storage Account diagnostic logs (blob/file access patterns)
- Azure SQL/Cosmos DB audit logs (data plane access attempts)
- PowerShell/Azure CLI command execution logs (if available via EDR)

Behavioral baselining over 30-90 days is essential to understand normal 
resource access patterns for each user and service principal. The detection 
system should track resource access frequency, scope, and temporal patterns 
to identify deviations. Integration with UEBA (User and Entity Behavior Analytics) 
platforms significantly enhances detection accuracy for this signal.
- **Entities**: Account, Resource, IP Address, API Call

## Signal MDR coverage
| Signal | Downstream MDR rules |
| --- | --- |
| Anomalous Azure AD Sign-In Patterns | _None_ |
| Service Principal Credential Abuse | _None_ |
| Privilege Escalation After Initial Access | _None_ |
| Suspicious Resource Enumeration and Access Patterns | _None_ |

## Relations
```mermaid
flowchart TB
subgraph "Signal"
11686b3d_5f9d_4c1e_b3a8_4bae83653d24["11686b3d-5f9d-4c1e-b3a8-4bae83653d24"]
12fb0e6a_a4e4_42d3_b77b_3c9c96f90f0b["12fb0e6a-a4e4-42d3-b77b-3c9c96f90f0b"]
353add53_6e14_47df_b65a_a591d2c6aacd["353add53-6e14-47df-b65a-a591d2c6aacd"]
d4d7e42b_3f9b_41c7_8dfb_ee7021ee806f["d4d7e42b-3f9b-41c7-8dfb-ee7021ee806f"]
end
subgraph "Threat"
2743bf18_3b86_4721_bf3e_153dcda0b149["Azure - Valid Credentials"]
end
f4a8b3c2_7e5d_4f1a_bc8e_9d2a6e7c8f0b["Detect Abuse of Valid Azure Credentials"]
f4a8b3c2_7e5d_4f1a_bc8e_9d2a6e7c8f0b -->|signal| 11686b3d_5f9d_4c1e_b3a8_4bae83653d24
f4a8b3c2_7e5d_4f1a_bc8e_9d2a6e7c8f0b -->|signal| 12fb0e6a_a4e4_42d3_b77b_3c9c96f90f0b
f4a8b3c2_7e5d_4f1a_bc8e_9d2a6e7c8f0b -->|signal| 353add53_6e14_47df_b65a_a591d2c6aacd
f4a8b3c2_7e5d_4f1a_bc8e_9d2a6e7c8f0b -->|signal| d4d7e42b_3f9b_41c7_8dfb_ee7021ee806f
f4a8b3c2_7e5d_4f1a_bc8e_9d2a6e7c8f0b -->|threat| 2743bf18_3b86_4721_bf3e_153dcda0b149
```
