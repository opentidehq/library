# Secrets stored in repository

## Metadata

- **UUID**: `ce7194f8-2398-4e79-b964-162ca5ee175b`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Secrets are digital authentication credentials such as encryption keys,
passwords, private keys, AWS secrets, Oauth tokens, JWT tokens, Slack
tokens, API secrets and others. Many of the organizations still keep
these secrets in plain-text hardcoded into source code, configuration
files or some of the configuration tools. (ref [1])    

Many developers use GitHub for personal projects and can happen to
leak by mistake corporate credentials even without rrealizing this.
Threat actors usually look first at the public repositories on GitHub,
and then at the ones owned by its employees. They use the collected data
to access company resources and databases and to compromise further the
infrastructure. They may use the collected data also for extortion
purposes threaten to publish it in public. (ref [2])  

This may pose a risk because the secrets could be stolen or leaked
without the knowledge of the internal staff. For example, they may be
accidentally or inadvertently committed in to the source code repository.
Once the secret is saved in history it is accessible and exposed to any 
malicious actor with read access.  

As a good practice make sure secrets are never stored in source code
and Software Control Management (SCM) or other configuration tools.
(ref [3])

Examples for secretes stored in repositories are:  

- Application Programming Interface (API) keys
- Database credentials
- Identity and Access Management (IAM) permissions
- Secure Shell (SSH) keys
- Certificates    

There is a growing need for organizations to centralize the storage,
provisioning, auditing, rotation and management of secrets to control
access to secrets and prevent them from leaking and compromising the
organization. Often, services share the same secrets, which makes
identifying the source of compromise or leak challenging. (ref [1])

## Techniques
- T1213.003
