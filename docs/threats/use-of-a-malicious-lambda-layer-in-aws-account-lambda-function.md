# Use of a malicious lambda layer in AWS account lambda function

## Metadata

- **UUID**: `2d3b113e-c6ad-492f-a6cb-1590a8d1191d`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A Lambda layer is an archive containing additional code, such as libraries,
dependencies, or even custom runtimes that is are extract to the /opt directory in the execution environment of the function they are added to. While AWS provides a few layers, developers
may also create custom ones to share in their organization, or use an external one
by pointing to a particular ARN. Layers are immutable, meaning once they are
created, a version is made and further changes would bump the version.
A threat actor can compromise one or more lambda functions by centrally 
compromising a lambda layer used by one or more other AWS accounts. This 
can also be a third party lambda layer in use by EC accounts. 

Once a new version of a lambda layer exists, it can  get deployed 
via some trigger+action needed on the side of the lambda administrator, 
unless the threat actor controls credentials to deploy or update lambda 
functions.

## Techniques
- T1648
- T1195.001
