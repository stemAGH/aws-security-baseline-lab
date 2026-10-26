# Evidence index

| Evidence | Actual scope | Limit |
| --- | --- | --- |
| [AWS live summary](aws-live-summary.json) | Stack; 19 passed checks; Config recording and two current compliant rule results | Two service/Region skips; no human MFA or restricted-role enforcement |
| [AWS behavior summary](aws-behavior-summary.json) | Six passed upload/access/retrieval checks | Secret retrieval as administrator; harmless test object retained by lifecycle |
| [CloudTrail correlation](cloudtrail-correlation.json) | Four matching management events in eight delivered log objects | Single Region; separate digest-integrity validation required |
| [Initial integrity attempt](cloudtrail-integrity-attempt.json) | Validation was attempted for the recorded interval | No digests found; INCOMPLETE, not a successful integrity test |
| [Successful integrity retest](cloudtrail-integrity.json) | 1/1 digest and 17/17 log files valid | Recorded available interval and single trail/Region only |
| [S3 guardrail](s3-account-guardrail.json) | All four flags saved On and verified after reload | No finding of an initially public bucket; not a complete access review |
| [Local campaign](local-simulation-20261025T025931Z.json) | Synthetic mail captured; automated click; capture flags false | No real-person campaign or human behavior measurement |
| [OpenVAS scan and retest](openvas-summary.json) | nginx 1.27.5 detected; upgraded to 1.30.6; same targeted selection went from two candidate alarms to zero | TCP80 service scope; alarms had QoD30; no authenticated full-host or exploit claim |
| [Test report](../docs/test-report.md) | Two templates linted; 23 offline tests; actual integrations | Synthetic fixtures do not establish live effectiveness |
| Budget console observation | Saved USD10 recurring budget; email inactive | Activation failed; alert delivery and spending cap not established |

Private raw outputs, account screenshots, credentials, QR codes, full scan reports and databases do not
belong here. `private-evidence/` is ignored and excluded from distribution. Summaries omit private account
identifiers and secret values.
