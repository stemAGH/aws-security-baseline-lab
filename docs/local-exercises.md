# Local scan and phishing exercises

These exercises run separately from AWS so scanner compute does not consume the $10 cloud budget.
Only owner-controlled lab assets and synthetic mail are in scope. A completed local campaign does not prove
that an AWS host was scanned or that employees received a phishing simulation.

## GoPhish and a local mail sink

`local/compose.yml` pins the downloaded official GoPhish and Mailpit images by digest. A Node helper runs the
HTTP client inside their internal Docker network. No service publishes a host port, and no SMTP relay is configured.
The admin API uses HTTP only inside this disposable isolated network; this configuration is unsuitable for hosting.
Anyone with Docker administration access can inspect the containers, so use a trusted local workstation.

From the repository root with Docker Desktop running:

```powershell
python scripts/run_local_simulation.py
```

The script starts only its named Compose project, creates one `learner@example.test` recipient, a clearly
labeled training message and a page with **both credential and password capture disabled**. Mailpit captures
the message. The script reads the local link and performs one automated click, verifies GoPhish recorded it,
then writes a sanitized JSON summary under `evidence/`. It removes its disposable containers and network in
a finally block. Images remain cached. It neither contacts a real recipient nor measures human behavior.

The API key is read from a temporary copy of this disposable lab's database, kept in process memory, passed
to the internal helper through standard input and not written to the evidence. Raw logs/database files must
not be committed. If a run is interrupted, inspect only this project and stop it with:

```powershell
docker compose -p aws-security-lab-local -f local/compose.yml down
```

A successful run must have a captured message, a Clicked Link result and disabled capture settings.
An API startup or delivery timeout is a failed attempt; keep it separate from a later successful run.
For a future real awareness exercise, obtain recipient/sender/landing-page approval and retention rules first.
Do not reuse this automated test result as a click rate for people.

## OpenVAS / Greenbone: targeted service exercise

The scanner runs inside Docker Desktop's Linux engine with an internal network, no published ports
and one disposable `lab-target` nginx service. Recorded versions: OpenVAS 23.51.0 and OSPd 22.10.6.
The baseline used nginx 1.27.5; the default delivered target is the fixed nginx 1.30.6. The [Compose recipe](../local/openvas-compose.yml) pins observed
image digests and identifies its official vendor source.

The first full-manager setup began importing the large SCAP/CVE catalog. It was stopped before any
scan; its incomplete catalog was later removed. The delivered exercise uses the official OSP scanner interface
and loaded vulnerability-test cache instead. It selects the 87 installed nginx-named tests plus SYN
port discovery, with automatic dependencies. This is a **targeted unauthenticated TCP80 service scan**.
It does not establish full-host patch coverage, an authenticated audit or a completed manager catalog.

The [selection manifest](../local/nginx-vt-selection.json) records the 88 explicit test IDs and source-file
hashes. The helper requires its matching feed version, enables safe checks, disables virtual-host
expansion and resolves only the owned `lab-target` service. It checks TCP80 connectivity before
submitting a scan. Dependencies can add further detection tests; 88 is the explicit selection count,
not a claim that every selected test ran or found a vulnerability.

### Reproduce the isolated workflow

Use the vendor hardware guidance and sufficient free disk. Initial feed copying and loading can take
minutes to hours. This run used approximately 6.6 GiB Docker memory. The full-manager import used much
more local disk than the scanner images; monitor free disk and do not remove unrelated containers.

```powershell
docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml -f local/openvas-target-baseline.yml up -d
Get-Content scripts/scan_local_target.py -Raw | docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml run --rm -T --no-deps --entrypoint python3 gvm-tools - ready
```

Wait for the helper to confirm the pinned feed version, completed cache hash and loaded nginx anchor test.
The version-only response in this run had a blank total; it is recorded as unknown, not zero tests. Enumerating every test's complete metadata is unnecessary and was expensive in this lab.
The interface is a private Unix socket available to this trusted Docker project; no administrator web UI
or credentials are exposed. Docker administrators already control the local containers.

```powershell
$env:LAB_VT_SELECTION = Get-Content local/nginx-vt-selection.json -Raw
Get-Content scripts/scan_local_target.py -Raw | docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml run --rm -T --no-deps -e LAB_VT_SELECTION --entrypoint python3 gvm-tools - start
Remove-Item Env:LAB_VT_SELECTION
```

Keep the returned scan UUID privately. Submission is not scan completion. Check the actual status, then
export the completed report to ignored private storage. The helper preserves scanner results.

```powershell
Get-Content scripts/scan_local_target.py -Raw | docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml run --rm -T --no-deps --entrypoint python3 gvm-tools - status YOUR_SCAN_UUID
New-Item -ItemType Directory private-evidence -Force | Out-Null
Get-Content scripts/scan_local_target.py -Raw | docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml run --rm -T --no-deps --entrypoint python3 gvm-tools - report YOUR_SCAN_UUID > private-evidence/openvas-baseline.xml
```

Confirm the report completed, the web service was detected and candidate findings have detection evidence.
Compare each candidate with the installed version and relevant configuration; a banner/version check does
not demonstrate exploitability. Record quality of detection and any unmet exploit conditions.
The default recipe pins the fixed image. After saving the old-target report, replace only the target:

```powershell
docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml up -d --no-deps lab-target
```

Repeat start/status/report with the **same selection and TCP80 scope**, saving a different report filename.
Preserve both original reports and interpret any remaining results before closing a finding.

### Recorded outcome

Both scans finished at 100 percent on 25 October 2026: baseline at 04:33:48 UTC and retest at
04:37:27 UTC. nginx 1.27.5 produced two candidate alarms, both QoD30; nginx 1.30.6 produced zero
with the same feed, selection and target address. NGINX-001 closes the obsolete-version condition.
The separate CVE-2025-53859 candidate concerns SMTP; the inspected target had HTTP listeners and
no active mail block. It was not established as an exploitable HTTP issue. QoD describes detection
confidence, not exploitation probability. See the [actual summary](../evidence/openvas-summary.json).

The delivered run removed its containers and network after saving both reports.
Stop only this local project after saving evidence:

```powershell
docker compose -p aws-security-lab-openvas -f local/openvas-compose.yml down
```

Seven scanner cache/configuration volumes and downloaded images remain local. Ten unused full-manager catalog volumes were removed. They are not AWS charges and are not public evidence.

## References

- [Official GoPhish container](https://github.com/gophish/gophish#docker)
- [GoPhish campaign API](https://docs.getgophish.com/api-documentation/campaigns)
- [Credential-capture flags](https://docs.getgophish.com/api-documentation/landing-pages)
- [Official Mailpit images](https://mailpit.axllent.org/docs/install/docker/)
- [Greenbone Community Containers and hardware requirements](https://greenbone.github.io/docs/latest/22.4/container/index.html)
- [Feed import and readiness](https://greenbone.github.io/docs/latest/22.4/container/workflows.html)
- [Scan configuration safety and limits](https://docs.greenbone.net/GSM-Manual/gos-24.10/en/scanning.html)

- [Official OSP interface](https://greenbone.github.io/python-gvm/api/ospv1.html)
- [nginx security advisories](https://nginx.org/en/security_advisories.html)

- [Greenbone quality of detection](https://docs.greenbone.net/GCS-Manual/gcs/en/glossary.html)
