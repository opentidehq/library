# Persistence through automation runbooks in Azure

## Metadata

- **UUID**: `50c7e353-ac1c-48a7-8c98-2515b45f31f4`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Persistence through automation runbooks in Azure is a robust and often-overlooked 
technique that allows attackers to maintain privileged access in cloud environments 
by leveraging Azure Automation Accounts and their associated runbooks.

### Attack Flow and Techniques

**1. Attack Lifecycle**  
- The attacker compromises an Azure account or system and escalates privileges, 
often to Global Administrator.
- After initial access is revoked or remediated, the attacker uses Automation Accounts 
to regain or maintain access to the Azure tenant.

**2. Runbook Creation and Modification**  
- Attackers create a new Automation Account with excessive privileges (such as "User Administrator" or "Subscription Owner") 
or leverage an existing one.
- A malicious runbook (typically a PowerShell script) is uploaded or an existing runbook is modified. These scripts can:
  - Create new Azure AD users or service principals with high privileges.
  - Deploy payloads (e.g., Cobalt Strike beacons) on Azure VMs.
  - Mimic legitimate processes through naming conventions (e.g., "SplunkDev" for Automation Account, "AzureAutomationMonitor" for runbook).

**3. Webhook Integration**  
- The malicious runbook is linked to a webhook, enabling remote execution via HTTP 
POST requests without direct authentication.
- This allows attackers to regain access on demand, even after their original accounts 
are removed.

**4. Privilege Retention and Escalation**  
- Automation Accounts are configured with password or certificate-based authentication, 
providing multiple avenues for re-entry.
- Attackers may assign or retain excessive permissions to ensure the malicious runbook 
can escalate privileges or create new backdoor accounts.

**5. Hybrid Runbook Workers**  
- Attackers may use Hybrid Runbook Workers, which run outside Azure’s sandbox and 
are not subject to the same execution time limits. This allows for more complex 
or long-running malicious tasks.

**6. Backdooring Packages and Runtime Environments**  
- Beyond runbooks, attackers can backdoor the packages and runtime environments 
(modules and Python packages) that support Automation Accounts. Malicious code can 
be embedded in these components, providing even deeper persistence.

## Techniques
- T1098
- T1204
