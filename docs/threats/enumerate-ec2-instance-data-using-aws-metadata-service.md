# Enumerate EC2 instance data using AWS metadata service

## Metadata

- **UUID**: `e7f05c4e-ca96-45e5-9788-116f802e1f32`
- **Schema**: `threat::1.0`
- **TLP**: clear

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

## Techniques
- T1119
- T1552.005
