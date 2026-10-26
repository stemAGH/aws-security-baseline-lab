# Match the resume to completed work

Use a claim supported by the completed scope:

> Deployed and tested a Sydney AWS security lab with account-level S3 Block Public Access,
> private SSE-KMS buckets, KMS rotation, management-event CloudTrail, two Config rules and
> a generated Secrets Manager secret. Verified 19 configuration checks, six behavior checks
> and real delivered log events; remediated and retested an S3 guardrail finding. Validated
> an isolated GoPhish workflow with synthetic mail and an automated click. Completed a targeted
> OpenVAS service scan, upgraded a legacy nginx target and verified a comparable retest.

This does not establish enforced human MFA, effective human least privilege, GuardDuty,
multi-Region coverage, secret rotation or an authenticated full-host audit. The owner chose to finish
within current project limits. Do not use the original full entry unchanged.

Current platform limits: the chosen new-experience project does not support multi-Region features or GuardDuty
without advanced features, and AWS manages human access roles. See [Lesson 2](lesson-02-identity-and-project-limits.md).
A saved cost budget with an inactive email recipient does not establish working cost alerts.

| Proposed claim | Evidence needed before using it |
| --- | --- |
| Hardened an AWS account | Defined scope; implemented settings; verification; remaining regional and service gaps |
| Least-privilege IAM with enforced MFA | Scoped effective permissions; relevant MFA path; allowed/denied tests; identity boundary |
| Multi-Region CloudTrail | Multi-Region setting; enabled Regions; event selectors; delivery and integrity checks |
| AWS Config rules | Recorder coverage; deployed rules; current evaluation results; missing-data treatment |
| GuardDuty | Detector/feature coverage and actual test evidence; distinguish generated samples |
| S3 Block Public Access with SSE-KMS | Account/bucket scope, key policies, encryption settings and relevant access/upload checks |
| Secrets Manager | Configured secret, scoped retrieval and evidence handling; rotation only if actually implemented |
| Scanned hosts with OpenVAS | Authorized target, feed/configuration details and completed scan output |
| Ran a GoPhish simulation | Approved recipients/environment, campaign execution and interpreted results |
| Tracked findings to closure | Original finding, remediation, comparable successful retest and closure approval |

Use the scoped statement above. The scanner exercise covered TCP80 and a pinned nginx-test selection;
two version alarms with QoD30 are not two confirmed exploitable vulnerabilities. The SMTP-related candidate
did not match the observed HTTP-only configuration. See the scan summary and vendor reference.
