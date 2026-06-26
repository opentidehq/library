# Cloning private repositories

## Metadata

- **UUID**: `4ac2b666-736a-42c5-9548-50393ea6bc46`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor can clone legit repositories, embed malicious code
but make them looks like legit. Their purpose is to entice a developer
to download and use the decoy repositories.    

Unauthorized cloning of private repositories is a form of IP theft.
Adversaries from external hackers to insiders aim to steal source code,
configuration details and secrets. The stolen information can be used
in multiple ways such as competitive advantage, discover vulnerabilities,
compromise other systems or mimic the original repositories to trick
developers into their rogue repository.  

After cloning of the repository, as a next step, the threat actor
spreads public available links from where a developer downloads its
malicious content.  

The threat actors employ various techniques to clone public or private
repositories, often with malicious intent. Some of the methods for
repository cloning include:  

### Misconfigured GitHub repositories

Threat actors exploit misconfigurations in GitHub, Gitlab or similar
repositories. They search for repositories with sensitive information
(such as API keys, credentials, or proprietary code) that have been
accidentally exposed. Once they find such repositories, they clone
them to their own accounts or local systems. By doing so, they gain
access to the codebase and any sensitive data within it ref [4].          

### Automated cloning and credential harvesting

In some cases, threat actors use automated tools to clone public
repositories. They specifically target repositories containing
Identity and Access Management (IAM) credentials. By cloning these
repositories, they harvest sensitive credentials, which can later
be used for unauthorized access, example in ref [5].            

### Repo confusion scheme

This scheme involves cloning existing repositories, Trojanizing them
(adding malicious code), and re-uploading them. The attackers hope that
the developers will mistakenly download the infected version.      

Once a threat actor has access to a CI pipeline, they obtain access key
or tokens to the SCM-Manager (ref [6]) and can perform action or operation
allowed for those credentials such as cloning private repository. This may
lead to unauthorized access to sensitive information and/or intellectual
property theft. Threat actors may identify weaknesses in the code and later
exploit them.      

A common command used for repositories cloning is:

git clone git://github.com/username/reponame.git

### Injection of a malicious code directly into exposed libraries

Some of the threat actor groups are observed to inject malicious code
directly into exposed libraries or submit fraudulent pull requests.
This technique can be used in a combination with repository cloning
to convey a malicious payload and infect developer systems and pilfer
sensitive files further ref [7].

## Techniques
- T1567.001
