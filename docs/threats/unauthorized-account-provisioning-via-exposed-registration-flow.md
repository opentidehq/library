# Unauthorized account provisioning via exposed registration flow

## Metadata

- **UUID**: `3d7dada6-5f9d-4f67-952e-faa2ab794fde`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
An adversary provisions an unauthorised account through exposed registration or account lifecycle
endpoints despite intended onboarding restrictions. The application may hide or remove the
registration UI, but backend routes such as /register, /signup, API registration endpoints,
password reset, or token issuance flows remain active and insufficiently gated.

The flawed workflow creates an account object before approval, invite validation, or domain
eligibility is enforced. Approval may be implemented only as a notification to a reviewer or a
manual delete process rather than as a blocking state transition. Once the account exists, related
flows may allow password reset, login, or token issuance for the unapproved account. Depending on
default role assignment and access checks, the adversary may gain partial or full access to the
application UI or APIs.

Detection and validation require replaying the lifecycle end to end: submit a registration request,
confirm account creation before approval, attempt password reset, and test whether a session or
token can be issued. The exposure may be systemic across deployments because registration paths
and account-state checks are reused across environments, cloud-hosted instances, or tenants.

The vector enables bypass of onboarding controls, internal enumeration from a trusted application
context, and a foothold for additional abuse. Severity should be finalised from evidence of the
endpoint, request and response pairs, reset behaviour, token issuance, and access level achieved.

## Techniques
- T1190
- T1136

## Chaining
```mermaid
flowchart LR
3d7dada6_5f9d_4f67_952e_faa2ab794fde["Unauthorized account provisioning via exposed registration flow"]
38adba1e_0961_4417_bd84_33fa9c42439f["Client-controlled session state authentication bypass"]
e2d8ce6b_f21e_4444_a828_0c6b722a9c93["Local user account added"]
3d7dada6_5f9d_4f67_952e_faa2ab794fde --> 38adba1e_0961_4417_bd84_33fa9c42439f
38adba1e_0961_4417_bd84_33fa9c42439f --> e2d8ce6b_f21e_4444_a828_0c6b722a9c93
```

## Relations
```mermaid
flowchart TB
3d7dada6_5f9d_4f67_952e_faa2ab794fde["Unauthorized account provisioning via exposed registration flow"]
3a73c153_abd7_40cd_86a5_4d57a42b9a44["Detect premature account activation and restricted onboarding bypass"]
7f6d1aae_c807_42fb_8734_4d3c6c4e9670["7f6d1aae-c807-42fb-8734-4d3c6c4e9670"]
958eeed6_43f6_43c8_8bb9_96397aab29a1["958eeed6-43f6-43c8-8bb9-96397aab29a1"]
d5906e6c_0f66_4dd6_8add_216a90b2b1f2["d5906e6c-0f66-4dd6-8add-216a90b2b1f2"]
3d7dada6_5f9d_4f67_952e_faa2ab794fde --> 3a73c153_abd7_40cd_86a5_4d57a42b9a44
3d7dada6_5f9d_4f67_952e_faa2ab794fde --> 7f6d1aae_c807_42fb_8734_4d3c6c4e9670
3d7dada6_5f9d_4f67_952e_faa2ab794fde --> 958eeed6_43f6_43c8_8bb9_96397aab29a1
3d7dada6_5f9d_4f67_952e_faa2ab794fde --> d5906e6c_0f66_4dd6_8add_216a90b2b1f2
```
