# What each part of the lab does

These explanations describe the intended lab. The selected project's actual availability and identity limits
are recorded in [Lesson 2](lesson-02-identity-and-project-limits.md). No explanation below establishes deployment.

## IAM and MFA

IAM controls access. A policy can restrict an operator to specific actions and lab resources. MFA strengthens
sign-in or the relevant role-assumption path, depending on the identity design. We must identify whether the
working identity is an IAM user, a federated identity or an assumed role before choosing an MFA policy.
The `aws:MultiFactorAuthPresent` condition is not a universal federation-MFA indicator.

Verification: an allowed action succeeds, an unrelated action is denied, and a role-assumption path that requires
MFA rejects an appropriate no-MFA attempt. Separate the caller policy, role trust and session permissions.

## CloudTrail

CloudTrail records selected AWS activity. A multi-Region trail covers enabled Regions and delivers records to
configured storage. Management events and data events are different categories; relevant data events need
explicit selection. We will verify the event, source Region, delivery and destination protection.

Enabling log-file integrity validation enables digest delivery; actual validation is a separate step. An empty
dashboard is not proof that there was no activity or that logging worked throughout a period.

## AWS Config

Config records supported resource configuration history and evaluates selected rules. It helps answer whether
a configuration changed and whether it matches a rule. It does not automatically prevent a bad change.
Recording and rule coverage are regional and resource-specific. Missing or insufficient data is not compliance.

Verification: confirm the recorder is running, inspect rule scope and evaluation timestamps, then perform an
approved benign test or inspect a relevant configuration change. Do not deliberately expose a bucket to prove detection.

## GuardDuty

GuardDuty analyzes supported telemetry to produce threat findings. It is regional, and optional protection features
have their own coverage and costs. A generated sample finding can exercise handling, but must be labeled as a
service-generated test rather than a real attack detected in the lab.

Verification: inspect enabled coverage, generate an appropriate service sample if approved, and document the
triage decision. Enabling a detector does not establish a working notification or response process.

## S3 Block Public Access and KMS

S3 Block Public Access helps prevent public exposure. Account-level and bucket-level settings have different
scope. Encryption protects stored data but does not authorize a caller; public access and encryption are separate checks.

SSE-KMS uses a KMS key for S3 server-side encryption. Key policies and IAM permissions determine who may use
the key. We will check default encryption and relevant upload behavior, not assume old objects were re-encrypted.
Key deletion can make retained evidence unreadable, so cleanup must account for retained encrypted objects.

## Secrets Manager

Secrets Manager stores and controls access to secrets. The lab should keep values out of source code, command
history, screenshots and public evidence. Rotation needs an actual supported integration or rotation workflow;
creating a secret does not establish rotation.

Verification: check metadata and scoped retrieval permissions without publishing the retrieved value.

## OpenVAS / Greenbone

OpenVAS is part of the Greenbone vulnerability-scanning stack. A useful scan needs an authorized target,
reachable services, loaded feeds and a documented scan configuration. Empty results can reflect poor coverage.
Start with an isolated lab target you own; no public target or unrelated network is in scope.

Verification: record the scope and feed state, review findings, remediate a confirmed issue and run a comparable
retest. A screenshot of a scanner dashboard does not prove findings were resolved.

## GoPhish

GoPhish supports phishing-awareness simulations. Our exercise will use only owner-controlled or explicitly
approved test recipients and a controlled mail environment. Start with click-only measurement; do not collect
passwords. Do not send a campaign until recipients, sender, landing page, timing and handling are reviewed.

Verification: document approval, test delivery and result interpretation. Opens and clicks can be affected by
mail-security scanners, so distinguish automated interaction from a justified human-response conclusion.

## Findings register

For every finding, record the asset, observation, risk, owner, treatment, evidence and retest. Keep findings Open
or Awaiting retest until evidence supports closure. Accepted risk is a separately authorized decision, not a successful fix.

## Primary references

- [IAM MFA context and policy behavior](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- [Multi-Region CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html)
- [CloudTrail KMS policies](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)
- [Config recorder behavior](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-configurationrecorder.html)
- [AWS Config delivery with KMS](https://docs.aws.amazon.com/config/latest/developerguide/s3-kms-key-policy.html)
- [GuardDuty detector configuration](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-guardduty-detector.html)
- [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/)
- [GoPhish landing-page capture options](https://docs.getgophish.com/python-api-client/landing-pages)

References checked 24 October 2026. Confirm actual versions, licenses, service availability and pricing before execution.
