# Test report — 25 October 2026

## Actual AWS results

- Baseline stack reached CREATE_COMPLETE; Config addition reached UPDATE_COMPLETE.
- At 03:50:34 UTC, the live verifier recorded **19 PASS, 2 SKIP**, PASS_WITH_LIMITS.
  GuardDuty and multi-Region coverage were intentionally skipped within the agreed project scope.
- Account and both lab buckets' public-access controls, non-public bucket policies, versioning,
  lab SSE-KMS key, key state/rotation, trail configuration/delivery and secret metadata passed.
- Config recording and both current exercise-bucket COMPLIANT evaluations passed. Snapshot delivery
  was separately observed SUCCESS; history delivery had no status yet.
- Six behavior checks passed at 03:33:17 UTC: default upload used the lab key; explicit AES256,
  another key and KMS without a key were denied; anonymous object read returned HTTP 403; the current
  administrator retrieved the generated demo secret. No secret value was printed or saved in evidence.
- At 03:49:17 UTC, eight delivered gzip log objects contained four GetBucketVersioning events matching
  the current principal, exercise bucket, account and Region. Raw identifiers are omitted from the summary.
- All four account-level S3 Block Public Access flags persisted On after saving and reloading.
  S3-001 is Closed for that specific preventive guardrail.
- At 04:36:35 UTC, CloudTrail validate-logs validated 1/1 digest files and 17/17 log files.
  The returned covered interval was 03:26:00-04:23:58 UTC; this does not validate future delivery.

## Offline and local integration results

Both templates pass **cfn-lint 1.58.0**, exit code 0. **23 offline unittest checks pass**;
their AWS fixtures are synthetic. Checks cover account mismatch, failed/missing API responses,
encryption-policy boundaries, delivery, current Config evidence, optional services, output handling,
auditor policy/MFA conditions, local tracking URL restrictions and Config startup order.

An actual isolated Docker integration created a GoPhish campaign for one synthetic `.test` recipient,
captured mail in Mailpit, performed an automated click and observed Clicked Link. Credential and password
capture were disabled. Its containers/network were removed; images remain cached. This establishes
workflow operation, not human awareness results.

OpenVAS 23.51.0 / OSPd 22.10.6 completed two isolated, unauthenticated TCP80 scans.
The selection contained 88 explicit nginx/discovery tests plus automatic dependencies, using feed
202610241320. Baseline nginx 1.27.5 completed at 04:33:48 UTC with two candidate alarms;
the same selection and target address completed against nginx 1.30.6 at 04:37:27 with zero alarms.
Both reports reached finished/100 percent and detected HTTP80 and the expected version.

The EOL candidate preserved native score 10.0 and QoD30; NGINX-001 closes only the obsolete-version
condition. The CVE-2025-53859 candidate also had QoD30 and concerns the SMTP module. Inspection found
HTTP listeners and no active mail block, so an exploitable HTTP vulnerability was not established.
Raw XML hashes and sanitized results are in evidence/openvas-summary.json. Containers and network
were removed; cached images and seven scanner volumes remain. The abandoned full-manager catalog
was never a completed scan and its ten unused volumes were removed.

## Problems found and corrected

1. The internal Docker network had no usable host ports. The campaign HTTP client moved into an internal
   helper, and published ports were removed.
2. SQLite's transaction context did not close the copied database on Windows. Explicit close fixed cleanup.
3. This GoPhish build requires a bare SMTP From address. A later complete run with that correction passed.
4. Initial CloudTrail verification preceded first delivery and failed correctly. Delivery arrived later;
   the retest passed. No failed attempt was relabeled successful.
5. Config creation stalled with a stopped recorder and no channel. Cancelled the update and observed
   UPDATE_ROLLBACK_COMPLETE. Creating the recorder with StartedOnCreate=false, then its dependent channel,
   completed successfully. Recording was explicitly started afterward.
6. The first post-start Config check lacked compliant evaluations. After evaluation, a fresh run passed
   both current-resource checks.

## Limits and open work

- MFA and restricted-human-role enforcement were not tested; the owner handles sign-in MFA.
- Administrator secret retrieval does not prove restricted-identity denial or rotation.
- Budget email activation failed; BUDGET-001 remains Open. The $10 target is not a spending cap.
- The OpenVAS result covers the selected HTTP service checks, not all ports or an authenticated host audit.
- No paid-plan upgrade, GuardDuty, multi-Region operation, real-person campaign, compliance certification
  or hosted GitHub CI run is claimed.

See the [evidence index](../evidence/README.md). Raw outputs/screenshots remain private outside the
project. KMS, secret and retained storage can continue charging.
