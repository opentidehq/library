# Use of a malicious lambda layer in AWS account lambda function

## Metadata

- **UUID**: `2d3b113e-c6ad-492f-a6cb-1590a8d1191d`
- **Schema**: `threat::1.0`
- **Version**: `1`
- **Created**: `2022-11-22`
- **Modified**: `2022-11-23`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e](https://levelup.gitconnected.com/cloud-security-table-top-exercises-629d353c268e)
- **2**: [https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html)
- **3**: [https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html](https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html)
- **4**: [https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html](https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html)
- **5**: [https://github.com/aws-amplify/amplify-cli/issues/6100](https://github.com/aws-amplify/amplify-cli/issues/6100)
- **6**: [https://lukemiller.dev/blog/jest-test-with-lambda-layers-mocking-a-ote-layer/](https://lukemiller.dev/blog/jest-test-with-lambda-layers-mocking-a-ote-layer/)
- **7**: [https://medium.com/devops-techable/how-to-work-with-lambda-layers-352ddb32f345](https://medium.com/devops-techable/how-to-work-with-lambda-layers-352ddb32f345)

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

## Criticality
**Low** - A Low priority incident is unlikely to affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **Requires that a threat actor can deploy code changes to a third party
or an EC controlled/deployed lambda layer in use by EC account(s), or 
that a threat actor can add a malicious lambda layer to a new or existing
lambda function.

Domains: Public Cloud
Targets: Serverless
Platforms: AWS Lambda**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Localised incident | A cyber attack on an individual, or preliminary indications of cyber activity against a small or medium-sized organisation. |
| Impact | Data Breach; IP Loss; Legal and regulatory; Nuisance; Operating costs | - |
| Leverage | Alter behavior; Dwelling; Information Disclosure; Infrastructure Compromise; Modify configuration; Modify data; Tampering | - |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Execution | Techniques that result in execution of attacker-controlled code on a local or remote system. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1648` | [Serverless Execution](https://attack.mitre.org/techniques/T1648) | Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers.   Adversaries may abuse these resources in various ways as a means of executing arbitrary commands. For example, adversaries may use serverless functions to execute malicious code, such as crypto-mining malware (i.e. [Resource Hijacking](https://attack.mitre.org/techniques/T1496)).(Citation: Cado Security Denonia) Adversaries may also create functions that enable further compromise of the cloud environment. For example, an adversary may use the `IAM:PassRole` permission in AWS or the `iam.serviceAccounts.actAs` permission in Google Cloud to add [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) to a serverless cloud function, which may then be able to perform actions the original user cannot.(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Rhingo Security Labs GCP Privilege Escalation)  Serverless functions can also be invoked in response to cloud events (i.e. [Event Triggered Execution](https://attack.mitre.org/techniques/T1546)), potentially enabling persistent execution over time. For example, in AWS environments, an adversary may create a Lambda function that automatically adds [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) to a user and a corresponding CloudWatch events rule that invokes that function whenever a new user is created.(Citation: Backdooring an AWS account) This is also possible in many cloud-based office application suites. For example, in Microsoft 365 environments, an adversary may create a Power Automate workflow that forwards all emails a user receives or creates anonymous sharing links whenever a user is granted access to a document in SharePoint.(Citation: Varonis Power Automate Data Exfiltration)(Citation: Microsoft DART Case Report 001) In Google Workspace environments, they may instead create an Apps Script that exfiltrates a user's data when they open a file.(Citation: Cloud Hack Tricks GWS Apps Script)(Citation: OWN-CERT Google App Script 2024) |
| `T1195.001` | [Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001) | Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise)    Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims. |
