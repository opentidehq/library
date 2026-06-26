# Named pipe creation using a predictable naming convention

## Metadata

- **UUID**: `db749144-8044-4479-ab34-bff22251a1d7`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor may deploy named pipes are part of an automation process to achieve a goal.
As example, this could be the Cobalt Strike keylogger deployment, where the cobalt Strike
operator merely clicks a button in the UI to deploy the keylogger, and behind the scenes 
this runs an automation on the compromised endpoint, which includes the creation of a named 
pipe, which in this case will have a predictable name, unless the CS operator changes this 
during the deployment (manual config in CS possible to deploy with custom named pipe name)

## Techniques
- T1056.001
