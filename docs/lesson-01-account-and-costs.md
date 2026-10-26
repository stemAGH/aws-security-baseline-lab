# Lesson 1: know the account before changing it

Planning ceiling confirmed by the owner: **US$10 per month**. The budget is saved; email delivery is not verified.
Review service costs and the proposed settings before enabling paid resources. Consider running exercises
sequentially and removing unneeded resources after verification; retained storage and keys also need review.

## Active target after the account switch

The owner confirmed **Caffeine Driven Development** as the lab project. The current access path uses an
existing managed role and IAM Identity Center, rather than the previous account's root session. Root MFA and
root-key observations from the previous account are not evidence about this project. The previous unsaved
budget draft and payment warning must not be carried over to the new target.

AWS Settings shows a free plan with credits. Distinguish project usage cost from amount due after credits.
Do not upgrade the plan, activate advanced features or create a different identity just to follow instructions
written for a conventional root/IAM-user account. First check available services and the actual identity model.

On 24 October 2026, created `aws-security-lab-monthly`: recurring monthly cost budget, fixed USD10,
all AWS services, unblended cost excluding credits and refunds. Alerts: actual cost at 85% ($8.50),
actual cost at 100% ($10), and forecast cost at 100% ($10). The recipient is the current account owner's
profile email; keep the address outside public evidence. No automatic budget actions are configured.

The saved details show **0/1 email verified**, with the recipient **Inactive**. Sending verification failed:
the console reported missing `notifications-contacts:CreateEmailContact`,
`notifications-contacts:SendActivationCode` and `notifications-contacts:ListEmailContacts` permissions.
No successful verification message or alert delivery was observed. This is finding BUDGET-001, still Open.
The new experience also restricts User Notifications configuration; the denial alone does not identify
whether an identity policy or an organization policy is responsible. Do not broaden an administrator role
as a guess. Seek the supported AWS resolution, then send verification, let the owner activate the contact,
and confirm its verified state. Contact verification alone does not prove a threshold alert was delivered.

If AWS reports a customer-verification issue, the account owner must resolve it directly in AWS Settings.
Keep identity documents and verification details out of this repository and chat. Do not change account plan or
verification settings to work around an unresolved account prerequisite.

## What an AWS account is

An AWS account is a boundary for resources, identities, billing and many security settings. We will use the
dedicated account you identified, rather than apply lab changes to an account used for unrelated work.

In a conventional AWS account, the **root user** is the original account identity and has especially powerful authority.
This project instead belongs to AWS Builder ID and has no root-user sign-in. A **working identity**
is an IAM or federated identity used for normal tasks. **Authentication** establishes who you are;
**authorization** determines what that identity can do. MFA strengthens authentication; it does not replace
least-privilege permissions.

## First action: sign in

Sign in directly in the AWS browser tab. Use an existing authorized administrative identity if you have one.
If you have only the root identity, tell the instructor after sign-in; we will plan the working identity setup
before normal lab operations. Enter passwords, MFA codes and recovery information only in AWS.

After sign-in, inspect the account menu to identify the account and whether you are using root, an IAM user or
a role. Do not publish the account ID or screenshots containing personal or billing details in the portfolio.
Account IDs are identifiers rather than passwords, but unnecessary disclosure is avoidable.

## Checks before enabling services

1. Confirm this is the intended dedicated lab account.
2. Check the current identity type. Do not create root access keys.
3. Inspect Builder ID MFA through AWS Settings > Manage security and sign-in. If social sign-in is used,
   check the upstream provider's MFA. The owner performs enrollment and retains recovery material securely.
   Device registration alone does not prove every working identity or API path enforces MFA.
4. Inspect current charges, the account plan/free-tier conditions and any already enabled services.
5. Agree a monthly planning ceiling and an alert destination controlled by the account owner.
6. Create appropriate budget alerts after reviewing their configuration. Alerts are notifications, not an automatic
   spending stop, and billing data/notifications can be delayed.
7. Choose a home Region and record which other Regions are enabled. Avoid interpreting the sign-in endpoint's
   Region as the intended deployment Region.
8. Inspect existing Config recorders, GuardDuty detectors, CloudTrail trails and account-level S3 public-access
   settings before adding or replacing anything. Even a dedicated account may have pre-existing resources.

## What we will not claim yet

We have not hardened the account merely by signing in. We will not claim MFA enforcement until the relevant
identity paths are tested, monitoring until delivery/coverage is verified, or finding closure until a retest supports it.

## Evidence to record privately

- Date, dedicated-account confirmation and current identity type.
- Builder ID/sign-in-provider MFA verification result without QR codes, seeds, recovery codes or authentication details.
- Budget amount, alert thresholds, notification setup and limitations.
- Home Region and coverage decisions.
- Initial service inventory and any conflicts requiring a separate plan.

Use the execution checklist. Keep raw evidence outside public Git and publish only reviewed, redacted copies.

## Questions you should be able to answer

1. Which identity owns this project, and which role performs console operations?
2. How are MFA and least privilege different?
3. Why does a budget alert not guarantee that charges stay under the budget?
4. Why inspect existing resources before deploying a security baseline?

Next: design the lab identities and resource boundaries before granting permissions.
