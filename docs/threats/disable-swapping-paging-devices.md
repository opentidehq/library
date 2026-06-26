# Disable swapping paging devices

## Metadata

- **UUID**: `497ccceb-c012-4830-aa61-4a046e7b6ce9`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Disable Swapping/Paging Devices is a tactic adversaries may employ to impair defenses, 
hamper forensic analyses, or disrupt normal system operations. 
By turning off, deleting, or misconfiguring the system’s paging file or swap space, 
malicious actors can limit the ability of the operating system to manage memory efficiently.  

## Evade Detection : Certain security tools or analysis processes rely on paging 
and memory snapshots. Disabling the swap or page file can complicate memory captures, 
obstructing forensic investigators from retrieving certain artifacts.  

## Cause Operational Instability : Without a functioning page file, systems may slow down 
or crash once physical RAM is fully consumed. This can be used intentionally to disrupt 
business operations or create an opening for other malicious activities 
while defenders are distracted.  

## Hide Malicious Components : Some malware frameworks attempt to evade detection 
by maintaining all malicious code in volatile memory. If system memory is not paged to disk, 
there is a slimmer trail of evidence left in permanent storage (e.g., pagefile.sys in Windows).  

### Windows 
```powershell
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" delete
```
This sequence disables the automatic page file management 
and removes the page file on the C: drive.

### Linux
```bash
swapoff -a
sed -i '/swap/d' /etc/fstab
```
This one disable all swap spaces and remove swap references from `/etc/fstab`, 
ensuring the change persists on reboot.

## Techniques
- T1562.001
