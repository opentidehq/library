# Scheduled tasks to connect to adversarial infrastructure

## Metadata

- **UUID**: `08b47a3b-fe90-4c9e-97f0-aa7bae361db1`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
A scheduled task is a task that is set to run automatically at a specific
time or interval. 

In the context of connecting to adversarial infrastructure,
a scheduled task would be a task that is set up to automatically establish
a connection to C2 infrastructure to check for 'orders' at a specified time
or interval. 

This could involve running a script that usually establishes an outbound 
connection. The exact details of how the task is set up would depend on the 
specific adversarial infrastructure being used and the tools and protocols 
available for connecting to it.

## Techniques
- T1053.005
