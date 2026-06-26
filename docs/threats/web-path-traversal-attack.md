# Web Path Traversal Attack

## Metadata

- **UUID**: `b330d3a8-1783-4210-9fec-11e6ecfe135e`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
Directory traversal (also known as file path traversal) is a web security
vulnerability that allows an attacker to read arbitrary files on the server
that is running an application. 

By manipulating variables that reference files with “dot-dot-slash (../)”
sequences and its variations or by using absolute file paths, it may be
possible to access arbitrary files and directories stored on file system
including application source code or configuration and critical system files.

## Techniques
- T1083
