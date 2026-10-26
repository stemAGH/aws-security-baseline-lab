# AWS Security Baseline Lab

A guided hands-on project for learning AWS security controls and collecting evidence that they work.

**Execution status:** deployed a Sydney baseline in the owner-confirmed dedicated AWS project.
CloudFormation reached CREATE_COMPLETE for the baseline and UPDATE_COMPLETE for the Config addition.
Account S3 Block Public Access is On. Live checks verified both private, versioned SSE-KMS buckets,
key rotation, management-event CloudTrail delivery and the generated demonstration secret's metadata.
Six behavior checks passed, including encryption-policy denials, anonymous-read denial and administrator
secret retrieval without exposing its value. Config recording and both current compliant rule evaluations passed verification.

CloudTrail integrity validation passed for one digest and 17 log files in the recorded interval.
The isolated GoPhish workflow completed with one synthetic recipient, Mailpit capture and an automated click.
Credential capture stayed disabled. A targeted OpenVAS TCP80 scan detected nginx 1.27.5 and two low-confidence
version alarms. After upgrading the owned target to 1.30.6, the same selection detected the new version and
reported zero alarms. NGINX-001 is closed for that legacy-version condition. Local containers/network were removed.
The owner chose to finish within current account limits: GuardDuty and multi-Region operation are excluded.
Human least-privilege enforcement and MFA remain unverified; the owner handles sign-in MFA.

**Build status:** two CloudFormation templates pass cfn-lint 1.58.0; all 23 offline tests pass.
See the evidence index for actual results and their limits. Synthetic fixtures are not live evidence.

**Cost plan:** US$10 per month is a planning ceiling, not a spending cap. The recurring budget is saved,
but its email contact remains inactive after a notification-contact permission error. Do not rely on alerts.
The KMS key, secret and retained storage incur ongoing charges. No paid-plan upgrade was performed.

## Files and quick start

- [Deployment, verification and cleanup](docs/deploy-and-verify.md)
- [Optional restricted auditor / IAM-user MFA exercise](docs/iam-exercise.md)
- [Local GoPhish test and OpenVAS procedure](docs/local-exercises.md)
- [Study notes and 24 expected questions](docs/study-and-interview.md)
- [Interview PDF: steps, project details and 40 questions](docs/interview-guide.pdf)
- [Test report](docs/test-report.md) and [evidence index](evidence/README.md)

Run locally with Python 3.12+:

```powershell
python -m pip install -r requirements-dev.txt
cfn-lint infra/baseline.json infra/iam-auditor.json
python -m unittest discover -s tests -v
```

The GoPhish integration check additionally requires Docker. Run `python scripts/run_local_simulation.py`;
it starts a disposable internal network, verifies the local campaign and removes its containers afterward.
AWS deployment is a separate reviewed step, described in the deployment guide. No AWS credentials belong here.

## Learning sequence

For each stage, explain the control, its configuration, the verification and the remaining scope.
The checklist records completed work and exclusions; the table below describes the learning objectives.

| Stage | What you learn | Completion evidence |
| --- | --- | --- |
| 1. Account and cost safeguards | Builder ID versus project role; account scope; budgets versus hard limits | Account checklist, saved budget, alert delivery and sign-in MFA verification |
| 2. Identity design | Authentication versus authorization; least privilege and session scope | Identity/role diagram and permission test plan |
| 3. CloudTrail | Activity logging across enabled Regions; log delivery and integrity | Trail configuration, successful delivery and integrity-validation result |
| 4. AWS Config | Configuration history and detective rules | Recorder status, selected rule evaluations and explained gaps |
| 5. GuardDuty | Threat findings, regional coverage and triage | Detector configuration and a clearly labeled sample-finding exercise |
| 6. S3 and KMS | Public access controls, transport protection, encryption and key permissions | Bucket/key configuration and allowed/denied access checks |
| 7. Secrets Manager | Secret storage, retrieval permissions and rotation boundaries | Metadata and retrieval authorization tests; never publish secret values |
| 8. Least-privilege role and MFA tests | Restrict an operator to the lab resources and verify boundaries | MFA/no-MFA and allowed/denied action results |
| 9. OpenVAS / Greenbone | Scan scope, feed freshness, findings and retesting | Authorized scan, original finding, remediation and rescan evidence |
| 10. GoPhish | Authorized awareness simulation and measurement limits | Approved test recipients, click-only campaign and sanitized results |
| 11. Findings and closure | Distinguish a planned action from verified remediation | Finding register with owner, evidence and retest results |
| 12. Publish and explain | Reproducibility, limitations and defensible resume wording | Reviewed repository, architecture, evidence index and interview explanation |

Start with [Lesson 1](docs/lesson-01-account-and-costs.md). Read the
[service explanations](docs/services-explained.md) before enabling a service.
Use [Lesson 2](docs/lesson-02-identity-and-project-limits.md) for this project's identity model and feature limits.
Track execution in [the checklist](templates/execution-checklist.csv) and actual findings in
[the findings register](templates/findings-register.csv).

CloudTrail multi-Region coverage does not automatically make Config or GuardDuty multi-Region.
The selected home Region is Sydney (ap-southeast-2). No compliance or account-wide hardening
claim is established by a template, a green dashboard or this learning plan alone.
