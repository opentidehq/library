# Deletion of Security Descriptor (SD) value in registry for scheduled task

## Metadata

- **UUID**: `e2b93649-44d7-4007-9592-3baf79cd2b33`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A Security Descriptor (SD) is a data structure that specifies the security
attributes of an object in Windows operating system. These attributes
include the permissions and access rights granted to users and groups, as
well as any security measures that have been applied to the object.

Security Descriptor determines the users allowed to run specific task. If
the SD value is deleted within the registry tree path, this deletion
results in “disappearing” of the task from “schtasks /query” and Task
Scheduler.

Some malware families, for example Tarrask malware can use security
descriptors to create scheduled tasks that are hidden from the user and are
not visible in the Windows Task Scheduler. These tasks are used to execute
the malware's malicious payload, which can include installing additional
malware, stealing sensitive information, or disrupting the normal operation
of the infected system.

To evade detection, a malware modifies the security descriptor of the
scheduled task to grant only the SYSTEM account access to the task. This
means that other users and security tools will not be able to see or
interact with the task, making it more difficult to detect and remove.

Security professionals can use tools such as Sysinternals Autoruns and
Process Explorer to identify and remove these hidden scheduled tasks, as
well as other forms of malware that use security descriptors for defense
evasion.

## Techniques
- T1053.005
