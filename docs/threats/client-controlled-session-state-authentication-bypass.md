# Client-controlled session state authentication bypass

## Metadata

- **UUID**: `38adba1e-0961-4417-bd84-33fa9c42439f`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
An adversary bypasses authentication or authorisation by injecting or modifying client-controlled
session state in HTTP requests. The application treats cookies, Authorization headers, or other
request variables as trusted authentication context even when values are arbitrary, unsigned, or
user-controlled.

Typical vulnerable logic checks whether a value is present, whether a simple string equals an
expected flag such as Login=true, or whether an identifier such as AppUsername=Admin is supplied.
The server does not verify that the value was issued by the application, bound to a server-side
session, signed, protected by HMAC, or validated as a JWT or equivalent token. As a result, a
crafted request can be treated as an authenticated or privileged session.

Exploitation is low complexity. The adversary compares behaviour with no cookies or headers,
then resends the same request with injected or modified values. Indicators include access granted
after arbitrary values are supplied, privilege changes after cookie modification, or different
protected content returned based only on client-controlled values. The issue can be systemic
because the same flawed session handling is reused across endpoints, roles, or application modules.

The threat should be confirmed by before/after request evidence showing authentication bypass,
authorisation bypass, or privilege escalation through crafted cookies or headers. Severity depends
on whether the trusted fields represent identity, role, login state, or access flags, and on the
breadth of affected endpoints.

## Techniques
- T1190

## Chaining
```mermaid
flowchart LR
38adba1e_0961_4417_bd84_33fa9c42439f["Client-controlled session state authentication bypass"]
b0d6bf74_b204_4a48_9509_4499ed795771["Pass-the-cookie Attack"]
0663c192_cdeb_49a2_994c_4cc8e98f764e["Late access control enforcement via redirect body leakage"]
38adba1e_0961_4417_bd84_33fa9c42439f --> b0d6bf74_b204_4a48_9509_4499ed795771
b0d6bf74_b204_4a48_9509_4499ed795771 --> 0663c192_cdeb_49a2_994c_4cc8e98f764e
```

## Relations
```mermaid
flowchart TB
38adba1e_0961_4417_bd84_33fa9c42439f["Client-controlled session state authentication bypass"]
7ff9ea94_7bf4_4df5_83f1_7d3dc0174653["7ff9ea94-7bf4-4df5-83f1-7d3dc0174653"]
9ba566b6_bfed_4059_bdb1_50bb3cac3c29["9ba566b6-bfed-4059-bdb1-50bb3cac3c29"]
9bfe87d7_c197_4893_b7e1_829ab6d1fcf5["9bfe87d7-c197-4893-b7e1-829ab6d1fcf5"]
d4c509d7_f9ab_452a_a91d_4da040095414["Detect acceptance of forged web session context"]
38adba1e_0961_4417_bd84_33fa9c42439f --> 7ff9ea94_7bf4_4df5_83f1_7d3dc0174653
38adba1e_0961_4417_bd84_33fa9c42439f --> 9ba566b6_bfed_4059_bdb1_50bb3cac3c29
38adba1e_0961_4417_bd84_33fa9c42439f --> 9bfe87d7_c197_4893_b7e1_829ab6d1fcf5
38adba1e_0961_4417_bd84_33fa9c42439f --> d4c509d7_f9ab_452a_a91d_4da040095414
```
