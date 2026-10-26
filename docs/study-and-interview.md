# Understand and explain this project

Start with the real status in the README. Describe implemented infrastructure only after deployment and
verification; describe a template as a template. Use your own results when explaining a test.

## The project in one minute

"I deployed a Sydney AWS baseline using CloudFormation: private SSE-KMS buckets, a rotating key,
management-event CloudTrail, two Config rules and a generated demonstration secret. Nineteen live
configuration checks and six behavior checks passed. I matched real events in delivered logs and closed
an account S3 guardrail finding after retesting. The account has documented platform limits, and the owner
chose to exclude GuardDuty and multi-Region operation. My local GoPhish exercise used synthetic mail
and an automated click. MFA and restricted-human-role enforcement remain unverified."

"I also completed a targeted local OpenVAS service scan, upgraded nginx 1.27.5 to 1.30.6 and repeated the
same checks. The legacy-version finding closed after retest; low-confidence scanner alarms were triaged
against the actual configuration. This was a TCP80 service exercise, not a full-host patch audit."

## Expected questions and answers

| Question | What you should explain |
| --- | --- |
| What problem does the lab solve? | It makes security settings repeatable and gives each claim a verification step. It does not turn an account into a certified organization. |
| Why CloudFormation? | One declared stack shows what will be created. A change set makes additions and permission changes reviewable before execution. |
| How are IAM and MFA different? | IAM policies authorize actions/resources. MFA strengthens a sign-in or role-assumption path. A highly privileged session can still use MFA. |
| How does the auditor enforce least privilege? | It can list/read one exercise bucket and decrypt those objects through S3. It cannot write, read the log bucket or retrieve the secret. Effective permissions need live testing. |
| Is the auditor your current console identity? | No. It is an optional IAM-user assumption exercise for a suitable environment. The current project uses Builder ID and an AWS-managed human role. |
| Why not apply an MFA condition everywhere? | Federation and IAM-user context differ. MultiFactorAuthPresent is not a universal indication of upstream MFA. Test the actual identity path. |
| What does CloudTrail record? | This template selects read/write management events. It does not select S3 object data events or every possible event category. |
| Does a multi-Region trail make every service multi-Region? | No. Config and GuardDuty are configured and verified regionally. Even a multi-Region trail requires regional delivery/coverage evidence. |
| Why enable log validation? | CloudTrail delivers signed digests for integrity checking. This lab validated 1/1 digest and 17/17 log files in the recorded interval. Earlier attempts found no digests in the interval and stayed incomplete; enabling the setting alone was not enough. |
| What does Config add? | Resource configuration history and evaluations against selected rules. It is detective, does not prevent changes, and has explicit resource/Region scope. |
| What if Config returns no results? | The test is incomplete. INSUFFICIENT_DATA, stale evaluations or an empty report do not mean compliant. |
| What does GuardDuty add? | Managed threat detections from supported telemetry. A sample finding tests handling; it is not proof that a real attack was detected. |
| Why both public-access controls and encryption? | They solve different problems. An encrypted object can still be disclosed to an authorized or overly broad caller. Encryption does not fix a public policy. |
| Why a customer-managed KMS key? | It makes key policy, rotation and permissions inspectable. It adds cost and a separate availability risk if disabled/deleted. |
| Why do the service grants have SourceArn/SourceAccount conditions? | They constrain service use to the intended trail/account/Region and reduce confused-deputy exposure. They must still match the actual service request context. |
| Does default encryption rewrite old data? | No. Existing objects and versions need separate review; the upload test checks new-object behavior. |
| Why retain the key and buckets on stack deletion? | To avoid accidental evidence loss or unreadable retained data. Retention also leaves costs and a separate cleanup obligation. |
| Why Secrets Manager instead of a configuration file? | It centralizes secret access and auditing. The demonstration uses a generated value. Rotation and retrieval boundaries require additional tests. |
| Does the budget enforce $10? | No. It tracks cost and sends alerts when operational; billing can lag. In this lab the recipient was inactive, so alert delivery remains an open gap. |
| How do you prove vulnerability closure? | Preserve the original report, confirm the condition, remediate it and repeat comparable checks. Here nginx 1.27.5 became 1.30.6; both runs detected the service, and the same targeted selection went from two low-confidence alarms to zero. NGINX-001 closes the old-version condition, not every possible host vulnerability. |
| What does the local phishing test prove? | Campaign creation, SMTP capture and click-event recording work for a synthetic recipient. An automated click says nothing about human susceptibility. |
| What is SOC 2 alignment here? | The controls can support access, monitoring and change/configuration objectives, but a small lab cannot establish organizational SOC 2 compliance or certification. |
| What failed during the build? | Budget contact activation was denied and remains open. Local campaign network/SQLite/From-address issues were fixed and retested. Config initially stalled on recorder/channel startup order; rollback, explicit stopped creation and later start resolved it. First delivery/evaluation checks also ran too early; later fresh checks passed. |
| What would you improve for production? | Organizational identity/MFA enforcement, regional coverage, durable retention, alert routing, incident ownership, backups and regularly reviewed effective permissions. Scope and price these explicitly. |

## Practice without reading the answers

1. Draw the operator, trail, two buckets, key and secret. Mark the optional services.
2. Pick one PASS and explain exactly which API response or behavior supports it.
3. Pick one SKIP and explain why it cannot support the corresponding resume claim.
4. Explain a finding from observation through remediation and retest. If it is still Open, say so.
5. Explain which objects could keep costing money after stack deletion and why deleting the key too early is risky.
