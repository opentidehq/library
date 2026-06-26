# Modify Microsoft Sentinel Data Connector to impair Detections

## Metadata

- **UUID**: `48432b70-77c4-4f5a-9d66-75764c1777c6`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A threat actor may want to disable, remove or update the configuration of
Sentinel Connectors to act invisibly in Azure, which would impair the ability
of a SOC to receive alerts since it would stop log file ingestion into Azure
Sentinel. 

An attacker can do this either by deploying via API an ARM template, biceps
template, or other script/code element that can be used via Azure APIs,
using the Azure CLI or directly on the portal itself via a browser.

## Techniques
- T1562.008
