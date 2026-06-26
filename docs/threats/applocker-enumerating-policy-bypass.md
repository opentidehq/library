# AppLocker enumerating policy bypass

## Metadata

- **UUID**: `9a1aeae5-912e-492c-b5d4-8bce91a95dae`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Enumerating policy bypass in AppLocker refers to the process of identifying
and exploiting weaknesses or vulnerabilities in AppLocker policies to run
unauthorised applications.    

A threat actor can use various methods and tools to enumerate AppLocker
policies with the goal to find weaknesses in this protection mechanism and
to exploit its whitelisting. Some of them are listed below.

### Bypass AppLocker policies

- Renaming executables method - renaming malicious executables to match the
name of an allowed application. In this way a threat actor can hide their
real malicious executables and intend in order to bypass AppLocker policies. 
- Using alternative executable extensions - using alternative executable
extensions, such as .scr or .pif, to bypass AppLocker rules.
- Enumeration of AppLocker policies tools - a threat actor can use different
enumeration tools to check if AppLocker policies are on place and what they
are blocking.

### Enumerating AppLocker policies

AppLocker policies can be enumerated using the registry query functionality,
as show below ref [5],[6]:  

'reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\'

### Known tools for AppLocker policy enumeration

AppLocker is a Windows feature that allows administrators to control which
applications can run on a device. Threat actors often try to bypass or
enumerate AppLocker policies to execute malicious code.

- PowerShell: PowerShell is a powerful tool that can be used to enumerate
AppLocker policies. Threat actors can use PowerShell cmdlets like
`Get-AppLockerPolicy` to retrieve AppLocker policies and
`Test-AppLockerPolicy` to test whether a specific application is allowed
to run.
- AppLocker Bypass Tools: There are several tools available online that can
bypass AppLocker policies. For example, the tool named `AppLockerBypass` is
a tool that uses various techniques to bypass AppLocker policies. Another
tool used for this purpose is `BypassAppLocker`. This tool uses PowerShell
to bypass AppLocker policies.
- MSBuild: MSBuild is a legitimate Windows utility that can be used to build
and execute code. Threat actors can use MSBuild to bypass AppLocker policies
by executing malicious code.
- Rundll32 : RunDLL is a legitimate Windows utility that can be used to execute
dll. Threat actors can use RunDLL to bypass AppLocker policies.
- Regasm/Regsvr32: Regasm and Regsvr32 are legitimate Windows utilities that
can be used to register and execute DLLs. Threat actors can use these tools
to bypass AppLocker policies by executing malicious DLLs.
- Certutil: Certutil is a legitimate Windows utility that can be used to
manage certificates. Threat actors can use Certutil to bypass AppLocker
policies by executing malicious code.
- Wscript/Cscript: Wscript and Cscript are legitimate Windows utilities that
can be used to execute scripts. Threat actors can use these tools to bypass
AppLocker policies by executing malicious scripts.
- Invoke-AppLockerBypass: This is a PowerShell script that uses various
techniques to bypass AppLocker policies.
- SharpAppLocker: This is a C# tool that can be used to bypass AppLocker
policies.
- WinPEAS - WinPEAS is a powerful tool that can be used to audit and bypass
Windows security features, including AppLocker policies. For more details
related to WinPEAS Applocker enumeration usage check ref [2].

## Techniques
- T1218
