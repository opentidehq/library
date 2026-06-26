# Azure - Lateral movement abusing Cross-Tenant Synchronization

## Metadata

- **UUID**: `2fd1cddb-c66d-4a99-9779-31e32b67495e`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
When configuring CTS, an Azure source tenant will be synchronized with a target tenant, 
where users from the source can automatically be synchronized to the target tenant. 
When synchronizing users, the user is only pushed from the source and not pulled 
from the target, making this a one-sided synchronization.

However, if improperly configured, attackers who have already compromised a tenant and gained
elevated privileges may exploit this feature, to move laterally to other connected tenants.

Attackers must look for tenants with 'Outbound Sync' enabled, which allows syncing
to other tenants. Next step is to locate the app used for CTS syncing and modify
its configuration to add the compromised user into its sync scope,
gaining access to the other tenant's network.

This allows the threat actor to achieve lateral movement without requiring new user credentials.

## Techniques
- T1021.007
