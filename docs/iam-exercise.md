# Optional restricted auditor and MFA exercise

**Not deployed.** This template is for an approved IAM-user assumption path in a suitable standard/advanced
AWS account. It does not configure or verify Builder ID MFA, does not replace the current managed console role,
and must not be used as evidence of federated MFA enforcement.

`infra/iam-auditor.json` creates one role. Its trust policy accepts only the supplied existing IAM user in the
same account and requires `aws:MultiFactorAuthPresent=true`. It grants list/read access to the exercise bucket
and KMS decrypt through regional S3 for that bucket's object encryption context. It grants no write, secret-read,
IAM administration or log-bucket access. Sessions have a maximum duration of one hour. Bucket Keys are not
enabled in the baseline; enabling them changes the encryption context and requires a policy review.

Before deployment, review the exact trusted user's ARN, bucket name and key ARN. The caller also needs
permission to assume this specific role. Do not create an IAM user, credentials or a broad policy merely to
make the template work. An administrator may already have other access outside the role; test actions with
the actual assumed-role session, not the administrator's original credentials.

## Test sequence

1. Deploy the main baseline and upload one harmless object to the exercise bucket.
2. Review a separate CloudFormation change set for the auditor role with the existing approved user ARN,
   EvidenceBucketName and KeyArn. Creating the role is an access grant requiring review.
3. From that IAM user's authorized credentials, call AssumeRole without MFA. It must be denied. Do not log credentials.
4. The owner supplies MFA directly through their approved credential workflow. Assume the role with MFA;
   verify the resulting caller identity, then list and read the exercise object successfully.
5. Using that same restricted session, try an upload to the exercise bucket: it must be denied. Try reading a
   known existing object in the log bucket and GetSecretValue for the demo secret: both must be denied.
   Record action, target alias, UTC time and response code, never object contents or secret values.
6. Repeat the relevant allowed/denied tests after a policy change. A template check or a policy simulator
   result alone is not a successful live permission test.

If the no-MFA attempt fails for an unrelated missing caller permission, first establish that the caller can
assume the role with MFA. The paired result isolates the intended authentication boundary more convincingly
than one AccessDenied response. Record unresolved ambiguity rather than marking the test passed.

The offline tests cover selected policy conditions and allowed action boundaries. They are a small policy
model, not the AWS authorization engine; SCPs, resource policies, permissions boundaries and other effective
permissions still need live review.
