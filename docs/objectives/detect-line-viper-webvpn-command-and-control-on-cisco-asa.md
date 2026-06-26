# Detect LINE VIPER WebVPN Command and Control on Cisco ASA

## Metadata

- **UUID**: `8546b0d8-c9e1-4a51-bf64-2b93c4159ebf`
- **Schema**: `objective::1.0`
- **TLP**: clear

## Description
This detection objective targets the WebVPN-based command and control
channel used by the LINE VIPER implant on compromised Cisco ASA
devices. LINE VIPER abuses legitimate WebVPN client authentication
endpoints to deliver tasking payloads and receive exfiltrated data,
blending malicious traffic with expected VPN authentication flows.

The initial LINE VIPER shellcode delivery also exploits this same
WebVPN authentication mechanism: a crafted authentication request
embedding a partial PKCS7 certificate followed by shellcode triggers
the handler installed by the RayInitiator bootkit in the lina binary.

Detection is particularly challenging because the C2 channel uses
standard HTTPS on port 443 with valid WebVPN endpoint paths and
plausible XML request structures. Detection requires deep inspection
of WebVPN authentication traffic patterns, certificate artefact
analysis, and behavioural anomaly detection on the ASA device.

Detection investment is Major given the requirement for HTTPS
inspection capabilities, Cisco ASA syslog telemetry at the required
fidelity, and the need for network forensics tooling to analyse
encrypted traffic patterns against baseline WebVPN behaviour.

### Malformed PKCS7 Certificate in WebVPN Authentication Request
Detects WebVPN client authentication requests to a Cisco ASA
device where the certificate field contains a malformed or
partial PKCS7 structure, consistent with the LINE VIPER initial
shellcode delivery mechanism [1].

LINE VIPER is loaded via a crafted authentication request that
embeds a partial PKCS7 certificate immediately followed by
shellcode. A valid PKCS7/CMS structure has well-defined ASN.1
DER boundaries; a partial or truncated structure followed by
non-DER bytes is structurally invalid.

Detection approach:
- Monitor HTTPS POST requests to Cisco ASA WebVPN endpoints
  (typically `/+webvpn+/index.html`, `/CACHE/`, or equivalent
  authentication paths)
- Inspect the body for `config-auth` XML elements containing
  certificate data in forms fields
- Flag certificate fields that begin with a valid PKCS7/CMS
  DER header (0x30 0x82 or 0x30 0x80) but are truncated or
  followed by non-DER byte sequences
- Alert on WebVPN auth requests where certificate payload size
  is anomalously large (shellcode appended after partial cert)

This signal requires TLS inspection or out-of-band network
visibility (e.g., mirrored traffic, firewall deep inspection).

**Methodology**: Pattern Matching

### Anomalous XML Payload in WebVPN Authentication Form Elements
Detects WebVPN authentication requests where standard XML form
elements carry anomalously large, encoded, or encrypted payloads
inconsistent with legitimate VPN client authentication [1].

LINE VIPER embeds operator tasking data within device-type or
similar XML form fields of the WebVPN authentication request.
Legitimate WebVPN clients send short, predictable values in
these fields (e.g., device type strings of 5-30 characters).
Attacker-controlled requests embed base64-encoded or encrypted
blobs of significantly larger size.

Detection criteria:
- WebVPN XML `config-auth` requests where `device-type`,
  `platform`, or `opaque` elements exceed a defined size
  threshold (e.g., >512 bytes) or contain high-entropy content
- Requests with `aggregate-auth-version="2"` header but
  device-type field values that do not match known VPN client
  vendor strings
- Repeated WebVPN authentication attempts from the same source
  IP with varying large payloads in form fields (C2 tasking
  sessions)
- Authentication requests with Content-Type set to
  `application/x-www-form-urlencoded` but body conforming to
  XML rather than URL-encoded format

Baseline of legitimate WebVPN authentication traffic is required
to tune thresholds and reduce false positives from non-standard
VPN clients.

**Methodology**: Anomaly

### Non-Standard Content in Cisco ASA WebVPN Authentication Response
Detects Cisco ASA WebVPN authentication responses that embed
data in the XML `message` element in a manner inconsistent with
legitimate authentication outcomes [1].

LINE VIPER exfiltrates task results by returning them embedded
within the `message` element of the WebVPN XML authentication
response. Legitimate ASA authentication responses contain
human-readable error or status strings in this field (e.g.,
"Authentication failed", "Please enter credentials"). Attacker-
controlled responses will contain base64-encoded or encrypted
data blobs.

Detection criteria:
- WebVPN authentication responses (HTTP 200 OK) where the
  `message` XML element contains high-entropy, non-printable,
  or base64-like content
- Response `message` field length significantly exceeding
  baseline for authentication status messages (>200 bytes
  without expected authentication UI text)
- Responses including standard security headers
  (X-Frame-Options, Strict-Transport-Security) alongside an
  anomalous `message` element — legitimate denials typically
  include only basic HTML error pages
- Asymmetric session patterns: multiple auth requests from the
  same IP that generate non-standard XML responses rather than
  standard redirect or HTML authentication pages

Requires visibility into outbound ASA HTTPS responses, achievable
via inline inspection or traffic mirroring.

**Methodology**: Anomaly

## Relations
```mermaid
flowchart TB
8546b0d8_c9e1_4a51_bf64_2b93c4159ebf["Detect LINE VIPER WebVPN Command and Control on Cisco ASA"]
22e8fb52_d101_4d67_90b7_6e697c2dbb2d["22e8fb52-d101-4d67-90b7-6e697c2dbb2d"]
cef505da_e628_469b_ad75_1a19091d31a6["cef505da-e628-469b-ad75-1a19091d31a6"]
cff09577_eb0b_4ac9_9393_789dbe439b56["cff09577-eb0b-4ac9-9393-789dbe439b56"]
8546b0d8_c9e1_4a51_bf64_2b93c4159ebf --> 22e8fb52_d101_4d67_90b7_6e697c2dbb2d
8546b0d8_c9e1_4a51_bf64_2b93c4159ebf --> cef505da_e628_469b_ad75_1a19091d31a6
8546b0d8_c9e1_4a51_bf64_2b93c4159ebf --> cff09577_eb0b_4ac9_9393_789dbe439b56
```
