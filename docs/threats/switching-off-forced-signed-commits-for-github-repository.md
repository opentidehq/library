# Switching off forced signed commits for GitHub repository

## Metadata

- **UUID**: `cd1baed8-3ea8-42e1-a27d-9da9ddb2f5b8`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Development and DevOps teams may turn on signed commits to ensure that an 
attacker cannot commit code to a code repository of an organization by 
merely succesfully stealing an OAuth token of a developer. With forced 
commits, the attacker will be blocked from committing code changes to a
repository, essentially limiting the attacker from attaining lateral 
movement or similar objectives, unless the attacker turns off the forced 
commit policy.

## Techniques
- T1562
