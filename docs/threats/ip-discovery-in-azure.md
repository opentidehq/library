# IP Discovery in Azure

## Metadata

- **UUID**: `777e22c5-e47d-42a2-a803-42a101dee575`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
IP Discovery in the context of Azure refers to an adversary’s technique for identifying 
the public IP addresses associated with Azure resources. This activity is classified 
in the Azure Threat Research Matrix (ATRM) under **reconnaissance** tactics, because 
it is often one of the first steps attackers perform to understand the accessible 
surface of a target Azure environment.

#### Attack Flow and Methodology

1. **Initial Reconnaissance**  (see terrain)
  The attacker needs valid credentials or otherwise access to an Azure environment 
  
2. **Enumerating Resources**  
  Using the Azure Portal, the Azure CLI, PowerShell, or Azure REST APIs, they enumerate 
  resources—especially focusing on Virtual Machines (VMs) and Network Interfaces (NICs).

3. **Querying for IP Information**  
  The attacker issues read requests (such as `az network nic list`, `Get-AzNetworkInterface`, 
  or relevant API calls) to retrieve detailed information about NICs. Each NIC 
  object includes properties for associated public and private IP addresses.

4. **Mapping IPs to VMs**  
  From the NIC information, the adversary can link public IPs back to specific 
  VMs or other endpoints, thereby building a map of accessible resources and potential 
  entry points.

#### Attack Goals and Impact

- **Surface Mapping:** Generate a list of exposed public IP addresses and their 
associated Azure resources.
- **Prioritizing Targets:** Identify potentially vulnerable endpoints for direct 
attack (RDP, SSH, web services) or for scanning later.
- **Avoiding Detection:** Reconnaissance is “low and slow”—often blends in with 
administrative activity, making detection challenging unless closely monitored.

#### Example Attack Scenario

1. **Enumeration:**  
  ```
  az network nic list --query "[].{Name:name, IP:ipConfigurations[].publicIpAddress.id}"
  ```
  Or use the Azure REST API to enumerate all NICs and their attached public IPs.

2. **Data Correlation:**  
  Map discovered IPs to VMs using the relationships expressed in the Azure resource objects.

3. **Follow-Up:**  
  The attacker now has a list of direct IPs to probe for vulnerabilities 
  (e.g., open RDP or SSH ports, misconfigured firewalls).

## Techniques
- T1078
- T1526
- T1528
