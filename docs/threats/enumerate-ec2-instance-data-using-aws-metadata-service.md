# Enumerate EC2 instance data using AWS metadata service

## Metadata

- **UUID**: `e7f05c4e-ca96-45e5-9788-116f802e1f32`
- **Schema**: `threat::1.0`
- **Version**: `6`
- **Created**: `2022-11-30`
- **Modified**: `2023-01-05`
- **TLP**: clear (`TLP:CLEAR`)
- **Organisation**: EC DIGIT CSOC (`56b0a0f0-b0bc-47d9-bb46-02f80ae2065a`)

## References
### Public
- **1**: [https://hackingthe.cloud/aws/enumeration/account_id_from_ec2/](https://hackingthe.cloud/aws/enumeration/account_id_from_ec2/)
- **2**: [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- **3**: [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
- **4**: [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html)
- **5**: [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- **6**: [https://medium.com/@radhagayathripatel/retrieving-aws-ec2-instance-metadata-using-metadata-in-scripts-251bf18dbabf](https://medium.com/@radhagayathripatel/retrieving-aws-ec2-instance-metadata-using-metadata-in-scripts-251bf18dbabf)

## Description
Threat actors collect AWS IDs from EC instances by using AWS metadata
service that is running by default. AWS account ID is a unique identifier
that is used to identify an AWS account, AWS resource management or to
access to AWS services.

Threat actors can extract different elements from metadata service, for
example: 

- accountId
- architecture
- availabilityZone
- billingProducts
- devpayProductCodes
- marketplaceProductCodes
- imageId
- instanceId
- instanceType
- kernelId
- pendingTime
- privateIp
- ramdiskId
- region
- version

AWS metadata keeps information for the instance such as instance id,
AMI id, hostname, ip address, security groups, public-ip and others.
Instance metadata usually is divided into different categories. Instance
metadata build based on the category is specified with a new version
number. In some cases the instance metadata is available only when a new
build version is launched. The categories are classified for example by
elastic-gpu-id, role-name, instance-type, operation system (windows, mac or
linux), ami-id (Amazon Machine Image ID), public-ip, vhostmd and by the
version when category was released.

Examples: 

Category:                                        Version ID:
ami-id                                           1.0
block-device-mapping/ami                         2007-12-15
elastic-gpus/associations/elastic-gpu-id         2016-11-30
iam/security-credentials/role-name               2012-01-12
network/interfaces/macs/mac/public-hostname      2011-01-01

Threat actors can extract information from the AWS metadata service with
the user token and curl command. For curl commands - cURL tool is usually
used for automation of AWS metadata information collection. 

Tools like curl on *nix-based systems, or Invoke-Rest Method in PowerShell
on Windows are used for extraction of AWS metadata as they send GET requests
for data collection. AWS exposes an Instance Metadata endpoint on every EC2 
Instance at the address: http://169.254.169.254

Example: 

curl http://169.254.169.254/latest/meta-data/

OR

Curl command with a token for extraction of additional matadata information: 

TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document

Example for extraction of AWS metadata with bash script:

INSTANCEID=$(curl -sL http://169.254.169.254/latest/meta-data/instance-id)
$ echo INSTANCEID

## Criticality
**Medium** - A Medium priority incident may affect public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence.

## Terrain
> **In AWS, the metadata service can by design be queried from a running
instance. A threat actor needs to control an EC2 instance or a
vulnerability in a running application that enables querying the instance
meta data service remotely, such as a SSRF vulnerability.

Domains: Public Cloud
Targets: Web Application Servers, Control Server, Input/Output Server, Public-Facing Servers
Platforms: AWS, AWS EC2**

## Threat Assessment
| Dimension | Assessment | Description |
| --- | --- | --- |
| Severity | Moderate incident | A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government. |
| Impact | Nuisance | Small and mostly inconsequential to day to day operations, but noticed. |
| Leverage | Information Disclosure | Threat action intending to read a file that one was not granted access to, or to read data in transit. |
| Viability | Likely | Probable (probably) - 55-80% |
| Kill Chain | Collection | Techniques used to identify and gather data from a target network prior to exfiltration. |

## ATT&CK Techniques
| Technique | Name | Description |
| --- | --- | --- |
| `T1119` | [Automated Collection](https://attack.mitre.org/techniques/T1119) | Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals.   In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data.(Citation: Mandiant UNC3944 SMS Phishing 2023)   This functionality could also be built into remote access tools.   This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) to identify and move files, as well as [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538) and [Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) to identify resources in cloud environments. |
| `T1552.005` | [Unsecured Credentials: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005) | Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.  Most cloud service providers support a Cloud Instance Metadata API which is a service provided to running virtual instances that allows applications to access information about the running virtual instance. Available information generally includes name, security group, and additional metadata including sensitive data such as credentials and UserData scripts that may contain additional secrets. The Instance Metadata API is provided as a convenience to assist in managing applications and is accessible by anyone who can access the instance.(Citation: AWS Instance Metadata API) A cloud metadata API has been used in at least one high profile compromise.(Citation: Krebs Capital One August 2019)  If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources. Additionally, adversaries may exploit a Server-Side Request Forgery (SSRF) vulnerability in a public facing web proxy that allows them to gain access to the sensitive information via a request to the Instance Metadata API.(Citation: RedLock Instance Metadata API 2018)  The de facto standard across cloud service providers is to host the Instance Metadata API at <code>http[:]//169.254.169.254</code>. |
