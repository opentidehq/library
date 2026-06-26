# AppLocker bypass using DLLs

## Metadata

- **UUID**: `a73c2506-8584-4c0b-bfdc-52e33c8bd229`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
AppLocker bypass using DLLs involves exploiting the way Windows loads DLLs
into processes. An attacker can create a malicious DLL that mimics a
legitimate one, which is allowed to run by AppLocker. When a legitimate
application loads the malicious DLL, it can execute arbitrary code,
effectively bypassing AppLocker restrictions.

A threat actor can bypass AppLocker application whitelisting using DLL
libraries. The reason is that there is no a mechanism for blocking out some
of the default DLLs. 

Additionally, DLLs are not executed directly by the operating system;
instead, they are loaded into the memory space of a process. This makes
it challenging for AppLocker to detect and block malicious DLLs activities.

There are several techniques that can be used to bypass AppLocker
using DLLs:

- DLL Hijacking - a threat actor can create a malicious DLL with the same
  name as a legitimate DLL that is already allowed by AppLocker. When the
  legitimate application loads the DLL, it will load the malicious one
  instead, allowing the attacker to execute arbitrary code.
- DLL Preloading - a threat actor can create a malicious DLL that is loaded
  before the legitimate DLL. This can be done by placing the malicious DLL in
  a directory that is searched before the directory containing the legitimate
  DLL.
- DLL Side-Loading: An attacker can create a malicious DLL that is loaded by
  a legitimate application that is allowed by AppLocker. The malicious DLL can
  then execute arbitrary code.

### DLL hijacking mimics a legitimate DLL name in AppLocker

An attacker can create a malicious DLL with the same name as a legitimate
one, which is allowed to run by AppLocker. The malicious DLL is placed in a
directory that is searched before the legitimate DLL's location.

### Loading a malicious DLL

When a legitimate application loads the malicious DLL, Windows will load the
malicious DLL instead of the legitimate one. This allows the attacker to
execute arbitrary code, bypassing AppLocker restrictions.

### REGSRV32 binary can bypass AppLocker restrictions by executing malicious DLL

Regsvr32.exe is a trusted Windows binary which can be used to bypass
AppLocker restrictions by executing a malicious DLL (e.g., cmd.dll).
Since regsvr32.exe is typically allowed by AppLocker policies and doesn't
rely on cmd.exe or powershell.exe, it can be used to load and run arbitrary
code through exported functions like `DllRegisterServer`. This allows
attackers to execute commands or scripts while avoiding detection and
bypassing common application whitelisting controls ref [1].

### An example of AppLocker bypass using DLLs

As an example to bypass Windows AppLocker a threat actor can create a
malicious DLL named `search.dll` and place it in the `C:\Windows` directory.
When the Windows Search service loads the `search.dll` DLL, it will load the
malicious one instead of the legitimate one.

## Techniques
- T1218
