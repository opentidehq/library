# Use of legitimate still vulnerable drivers to elevate privileges

## Metadata

- **UUID**: `a5761988-391d-4cd3-8ade-690bd3315943`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Threat actors can use legitimate and code-signed, but vulnerable drivers to 
execute kernel-level code in order to elevate privileges or disable security 
products. Such drivers can allow malicious actors to manipulate system 
components, processes, maintain persistence on a system and evade security 
products ref [1].

Microsoft and other vendors have created and maintain vulnerable driver 
lists ref [2], [6], [7], for example to thwart and isolate drivers which are 
vulnerable or with a high risk for explaoitation. The drivers with a 
previously discovered vulnerabilites can also be considered for review and
as good candidates for a block list or monitoring.  

The vulnerable signed drivers can come from a variety of vendors such as,
but not limited to, ASROCK, ASUSTeK, IBM.  

### List of some vulnerable signed drivers, which have been exploited in 
the past

- `win32k.sys` - it's a kernel-mode driver that has been exploited in
   various ways, including elevation of privilege (EoP) vulnerabilities.
- `splwow64.sys` - this is a vulnerable driver which lets local code
  escalation by abusing the print stack broker.
- `dxgkrnl.sys` - this driver is responsible for graphics rendering and has
  been vulnerable to exploits. It's related to a validation flaw enabling
  local EoP in the DirectX graphics kernel driver.
- `tdx.sys`: The TDx driver has been exploited in the past, including a
  vulnerability that allows remote code execution (RCE). Other vulnerability
  buffer over-read allows local EoP on multiple Windows versions; patched
  July 2025.
- `splwow64.sys` - this driver is responsible for print spooling and has
   been vulnerable to exploits.
- `cng.sys` - the Cryptography Next Generation (CNG) driver has been
  exploited, including a vulnerability (CVE-2020-1145) that allowed EoP.
- `msrpc.sys` - it's Microsoft Remote Procedure Call (MSRPC) driver has been
  vulnerable to exploits. 
- `ucx01000.sys` - this driver is part of the USB driver stack and has been
  exploited. 
- `ndis.sys` - the Network Driver Interface Specification (NDIS) driver has
  been vulnerable to exploits. Example for an exploit: EoP precedent where
  buffer length checks were insufficient.  
- `wdf01000.sys` - this is Windows Driver Framework (WDF) driver which can
   be exploited by the threat actors for privilege escalation and other
   purposes.
- `storport.sys` - the Storage Port driver can be vulnerable to exploits.

## Techniques
- T1547.006
- T1068
- T1547
