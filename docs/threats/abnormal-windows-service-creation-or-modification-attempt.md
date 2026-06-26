# Abnormal Windows service creation or modification attempt

## Metadata

- **UUID**: `f16deda4-65b1-4825-8042-fe15524d0ce1`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor may attempt to create Windows services in order to start and
run software or scripts that allow the threat actor to perform actions that
controlling a Windows service allows to perform.   

This may include: Establishing persistence, runnning cryptominers, 
communicating with command&control, launching remote actions or moving 
laterally.  

Persistence using Windows service creation may be achieved in many ways, 
see TVMs chained from this one.   

Threat actors may try to evade detection by using well-known service names 
or names that very closely resemble something that would look legit on a 
Windows platform. For example  "WinHTTP Web Proxy Auto-Discovery" or 
"TCP/IP NetBIOS Help" [CRN-01]  

Some other example for creation/change of the current state of a service
may appaear on a DC (Domain Controller). For example, events in the
EventLog with ids: 7036, 7040, 7045 and 4697 indicate some of the possible
creation or modification of services on a DC.  

Creation or modification of a service on the system may lead to
altering in the binaries and registries of the affected system.
Such changes/modifications can also interfere with the other
processes related to other services on the system. Each service
has so called threads or sub-processes related to the main one.
A change in one service or its thread can impact or compromise
some of the related ones.

## Techniques
- T1543.003
- T1112
- T1055
