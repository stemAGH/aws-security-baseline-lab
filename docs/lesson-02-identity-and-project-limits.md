# Lesson 2: identity and the limits of this project

## What we observed

The owner selected the dedicated project **Caffeine Driven Development**. Console access uses an existing
IAM Identity Center managed role. The home Region is **ap-southeast-2 (Sydney)**. These observations identify
the access path; they do not prove least privilege or MFA enforcement. MFA inspection remains pending.

## Authentication and authorization

Authentication answers "Who signed in?" MFA adds a factor to that sign-in. Authorization answers "What may
this identity do?" A successful MFA sign-in can still lead to a role with excessive permissions.

AWS's new experience uses Builder ID to own project accounts, with AWS-managed human access roles and
organization policies. There is no project root-user sign-in. IAM users and roles created within a project
are for programmatic access, not a replacement console sign-in. Do not create long-lived access keys for
this lesson or treat `aws:MultiFactorAuthPresent` as proof of federated MFA.

## Read the platform boundary before designing controls

| Lab component | Current platform status | Consequence for the lab |
| --- | --- | --- |
| CloudTrail | Listed for the new Free Tier; multi-Region features unsupported | A single-Region exercise is possible subject to account access; it cannot support the proposed multi-Region claim |
| Config, S3, KMS, Secrets Manager | Listed for the new Free Tier | Inspect existing settings and estimate charges before enabling anything; availability does not mean zero cost |
| GuardDuty | Listed as unsupported without advanced features | Record a coverage gap; no GuardDuty detector or sample finding has run |
| Human least privilege | AWS manages project human access roles | Do not claim a custom restricted console operator was implemented |
| User Notifications | Configuration operations restricted | Budget exists, but contact activation failed; delivery remains an open finding |

Source availability is not an execution test. Account verification and effective policies can still prevent
listed services from working. The owner must resolve the account-verification issue directly in AWS.

## Your MFA check

1. Open AWS Settings and select **Manage security and sign-in**.
2. Inspect the Builder ID **Security** page. If sign-in uses an external provider, inspect that provider's MFA.
3. Record only the device type/status and date. Do not capture a QR code, seed, recovery code or OTP.
4. If registration is needed, the owner completes it directly in AWS, including secret entry and submission.
5. Verify a fresh sign-in through the intended path. Trusted-device behavior can suppress a prompt;
   a missing prompt alone is not proof that MFA is disabled. Document the limits of the check.

## Decide scope before upgrading

We can continue a partial lab on this project, recording unsupported controls explicitly. The full proposed
resume entry needs an environment that supports GuardDuty, multi-Region operation and the intended human
permission design. A standard account created through AWS's advanced sign-up is another setup option;
it has not been created for this lab.

Activating advanced features on this organization requires a paid-plan upgrade, is irreversible and removes
project spend limits. It transfers governance responsibilities to the owner. No upgrade or activation has been
performed or approved here. The $10 budget is an alert mechanism, not a spending stop.

## Explain it in your own words

- Why can a managed administrator role still receive AccessDenied?
- What is the difference between a budget being saved and its alerts being operational?
- Why is a single-Region trail insufficient evidence for a multi-Region resume claim?
- What evidence separates MFA registration from MFA enforcement?

## Official references

Checked 24 October 2026; recheck before configuration changes.

- [Account and access model](https://docs.aws.amazon.com/accounts/latest/reference/sign-up-for-aws.html)
- [Supported services and restrictions](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html)
- [Builder ID MFA through AWS Settings](https://docs.aws.amazon.com/accounts/latest/reference/register-mfa-devices.html)
- [Advanced-feature effects and prerequisites](https://docs.aws.amazon.com/accounts/latest/reference/activate-advanced-features.html)
