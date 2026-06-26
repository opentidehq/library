# Late access control enforcement via redirect body leakage

## Metadata

- **UUID**: `0663c192-cdeb-49a2-994c-4cc8e98f764e`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
An adversary exploits a broken access control pattern in a web application
where the server constructs and includes the full rendered page content in
the HTTP response body before enforcing authentication or authorisation
checks. When the access control check fails, the server issues an HTTP 302
Found redirect response with a Location header pointing to a login or error
page — however, the response body still contains the complete protected page
content.

Standard web browsers automatically follow the redirect and do not display
the body content to the user, masking the data leakage. However, an attacker
using HTTP clients that do not follow redirects (e.g. curl, Burp Suite, or
custom scripts) can intercept and read the full protected content from the
redirect response body.

This vulnerability affects authenticated and role-restricted web pages in a
pattern-based manner, meaning it is not isolated to a single endpoint but
rather stems from a systemic flaw in the application's access control
enforcement architecture. The root cause is a late enforcement model where
the application constructs the complete response — including sensitive data —
before determining whether the requesting user is authorised to view it.

Exploitation is trivial once the pattern is discovered: the adversary simply
sends HTTP requests to protected endpoints and inspects the response bodies
of 302 redirect responses. No authentication tokens, session cookies, or
special headers are required. The attack can be automated to enumerate and
exfiltrate content from all affected endpoints systematically.

This aligns with OWASP Top 10 A01:2021 Broken Access Control and CWE-284
Improper Access Control. The vulnerability represents a fundamental flaw in
the application's security architecture rather than a simple misconfiguration.

## Techniques
- T1190

## Relations
```mermaid
flowchart TB
0663c192_cdeb_49a2_994c_4cc8e98f764e["Late access control enforcement via redirect body leakage"]
0770d2a4_9299_46d7_93f2_c3fff68aad26["0770d2a4-9299-46d7-93f2-c3fff68aad26"]
077ee487_7694_4ed5_9a83_5ed36b4f31c5["077ee487-7694-4ed5-9a83-5ed36b4f31c5"]
f798884c_46ea_424c_9958_45f2c4f8110a["f798884c-46ea-424c-9958-45f2c4f8110a"]
f8a95fcf_c5b0_4db0_bb8b_78e4edaa0544["Detect protected content in abnormal redirect responses"]
0663c192_cdeb_49a2_994c_4cc8e98f764e --> 0770d2a4_9299_46d7_93f2_c3fff68aad26
0663c192_cdeb_49a2_994c_4cc8e98f764e --> 077ee487_7694_4ed5_9a83_5ed36b4f31c5
0663c192_cdeb_49a2_994c_4cc8e98f764e --> f798884c_46ea_424c_9958_45f2c4f8110a
0663c192_cdeb_49a2_994c_4cc8e98f764e --> f8a95fcf_c5b0_4db0_bb8b_78e4edaa0544
```
