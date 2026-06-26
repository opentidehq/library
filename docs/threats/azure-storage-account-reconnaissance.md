# Azure - Storage account reconnaissance

## Metadata

- **UUID**: `53f4e2f0-7d11-4629-bb26-905993a589db`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Azure storage account reconnaissance refers to the initial phase of cyberattacks 
where adversaries gather information about target storage accounts to identify vulnerabilities 
and plan subsequent attacks. This threat vector is critical as it enables attackers 
to map out potential entry points and weak configurations in cloud storage environments.

### Techniques and Methods  
**Storage account discovery**:  
- Attackers use methods like DNS reconnaissance (e.g., searching `*.blob.core.windows.net` subdomains) 
and brute-forcing account names to identify active Azure storage accounts.  
- Publicly available tools such as **Microburst** and **BlobHunter** automate the 
enumeration of storage accounts and containers.  

**Public container/blob enumeration**:  
- Adversaries exploit misconfigured public access settings (e.g., containers set to "container" or "blob" access levels) 
to list and access sensitive data without authentication.  
- Techniques include analyzing DNS records, web page source code, and cloud metadata 
for storage account URLs.  

### Attack Implications  
Successful reconnaissance can lead to:  
1. **Data exposure**: Identification of publicly accessible containers with sensitive data.  
2. **Lateral movement**: Discovery of storage accounts linked to higher-privileged 
resources (e.g., Azure Functions) for token theft and privilege escalation.  
3. **Malware distribution**: Mapping storage accounts used for hosting malicious 
content via features like static websites.

## Techniques
- T1530
- T1078.004

## Chaining
```mermaid
flowchart LR
53f4e2f0_7d11_4629_bb26_905993a589db["Azure - Storage account reconnaissance"]
41f57a57_1ed6_407e_bb70_a0f6ab52af10["Azure - Storage Blobs Reconnaissance"]
2743bf18_3b86_4721_bf3e_153dcda0b149["Azure - Valid Credentials"]
b1593e0b_1b3b_462d_9ab6_21d1c136469d["Azure - Gather Resource Data"]
53063205_4404_4e6d_a2f5_d566c6085d96["Data collection using SharpHound, SoapHound, Bloodhound and Azurehound"]
53f4e2f0_7d11_4629_bb26_905993a589db --> 41f57a57_1ed6_407e_bb70_a0f6ab52af10
41f57a57_1ed6_407e_bb70_a0f6ab52af10 --> 2743bf18_3b86_4721_bf3e_153dcda0b149
2743bf18_3b86_4721_bf3e_153dcda0b149 --> b1593e0b_1b3b_462d_9ab6_21d1c136469d
b1593e0b_1b3b_462d_9ab6_21d1c136469d --> 53063205_4404_4e6d_a2f5_d566c6085d96
```
