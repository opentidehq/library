# Cloud IAM role assumption

## Metadata

- **UUID**: `f1dc4341-eb45-4d07-8075-b1a6b227cc76`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Once adversaries gained a set of creentials, they will
try to discover and leverage identity policies to increase their
control over the infrastructure. This is especially the case for
instance credentials, which can be stolen through exploitation.

Changing roles will allow the adversary to assume a
more powerful role, escalate privileges and eventually move further
in the cloud to achieve objectives. This can be particularly
impactful if cross account roles are leveraged.

## Techniques
- T1098.003
