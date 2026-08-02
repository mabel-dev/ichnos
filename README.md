# ichnos

Internet measurement service: ZMap discovers responsive hosts, ZGrab2 fingerprints
them, and results are batched hourly into [Opteryx](https://opteryx.app) via the public
`opteryx-upload` client. Full design rationale lives in the
[`scan.opteryx`](../scan.opteryx/DESIGN.md) design document - this repo is the
implementation of that design's Phase 3 (HTTP/HTTPS-only MVP).

**Live site:** <https://ichnos.online> (see [`/responsible-scanning`](https://ichnos.online/responsible-scanning)
if you've noticed a connection from this project) &middot; **Abuse contact:**
[abuse@opteryx.app](mailto:abuse@opteryx.app)

This project follows [ZMap's Scanning Best
Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices) for rate
limiting, target selection, and exclusion handling.

## Scope (MVP)

- **Protocols**: HTTP and HTTPS only.
- **Discovery vs refresh**: `scan` runs native ZMap discovery (rate-limited via ZMap's
  own `--rate`, 1 pps by default) over addresses that aren't already known-responsive,
  continuously. `refresh` re-tests every already-known-responsive host directly via
  ZGrab2 (no ZMap involved) to detect drift, on a more relaxed cadence. See `cli.py`'s
  module docstring and `scanner.py`'s `run_scan`/`run_refresh_scan`.
- **Rate**: discovery is throttled by ZMap's own native `--rate`, not this project's
  token bucket. The token bucket (`ratelimit.py`, default one request per 5 seconds)
  still paces `refresh` and the ad-hoc `scan --target` path, where there's no ZMap
  invocation to throttle discovery-style.
- **Jurisdiction pre-exclusion**: Japan, North Korea, South Korea, China, Russia, and
  Iran are excluded from scanning as comprehensively as country-level IP allocation
  data allows (see `jurisdiction.py`). This is best-effort, not a guarantee - see the
  module docstring.
- **Publish**: hourly, via the Opteryx Upload Service's public API - this service never
  touches Opteryx internals.

This is a prototype scoped to prove the pipeline end-to-end, not to achieve broad
Internet coverage. Raising the rate, adding protocols, and distributing across workers
are explicitly deferred - see the design doc's scaling strategy.

## Layout

```
src/ichnos/
  models.py         # Exclusion, ScheduleEntry, ScanMetadataRecord, CurrentStateRecord, ...
  storage/          # storage interfaces + in-memory (dev) and DynamoDB (real) backends
  ratelimit.py      # global token-bucket throttle
  blocklist.py      # merges bogons + self-serve opt-outs + jurisdiction CIDRs
  jurisdiction.py   # weekly job: RIR delegated-stats (or ipdeny fallback) -> CIDR list
  normalize.py      # extracts protocol-relevant fields from raw ZGrab2 JSON
  fingerprint.py    # canonicalize + hash normalized fields -> fingerprint_id
  scanner.py        # native ZMap discovery (run_scan) + known-host refresh (run_refresh_scan)
  publish.py        # batches changed rows and commits to Opteryx via opteryx-upload
  webapp/           # public info page, Responsible Scanning page, security.txt/
                    # scanner.txt, self-service opt-out (FastAPI)
  cli.py            # `ichnos scan|refresh|publish|jurisdiction-refresh|serve`
```

## Requirements to actually run scans

`zmap` and `zgrab2` must be installed on the host, and `zmap` needs raw-socket
privileges (root, or `cap_net_raw+eip` on the binary) - this package shells out to both,
it does not vendor or reimplement them. Nothing in this repo will send real network
traffic unless those binaries are present; the test suite never invokes them (all
subprocess calls are dependency-injected and mocked in tests).

## Install

```bash
pip install -e ".[dev]"
# DynamoDB backend (the real deployment target) needs boto3:
pip install -e ".[aws]"
```

## CLI

```bash
# Rebuild blocklist (excluding already-known-responsive hosts), run native ZMap
# discovery, stage results locally:
ichnos scan --protocol http --candidates 12 --store memory

# Re-test every currently-known-responsive http host directly via ZGrab2 (no ZMap),
# to detect drift since it was last seen:
ichnos refresh --protocol http --store memory

# Commit whatever's staged to Opteryx (needs ICHNOS_OPTERYX_CLIENT_ID/_SECRET):
ichnos publish

# Rebuild the JP/KP/KR/CN/RU/IR pre-exclusion list (weekly job):
ichnos jurisdiction-refresh --source rir

# Run the public info page + opt-out form:
ichnos serve --store memory
```

`--store memory` is for local dry runs only - it doesn't persist between process
invocations, so it's not meaningful for `scan`/`publish` in anything but a same-process
demo. Real deployment uses `--store dynamodb` (the default), backed by the tables named
in `config.py` / `ICHNOS_*_TABLE` env vars.

See `cli.py`'s module docstring for how `--candidates` relates to ZMap's native `--rate`
and cron's invocation interval - sizing it wrong either leaves most of the window idle
or lets a run overrun into the next cron tick.

## Configuration

All settings are environment variables, prefixed `ICHNOS_` - see `config.py` for the
full list (table names, blocklist paths, rate interval, Opteryx workspace/collection,
PAT credentials). Nothing is hardcoded so schedule/rate/target changes don't need a
redeploy, per the design doc's operational model.

## Tests

```bash
pytest
```

Every module above is written against dependency-injected interfaces (a `run_command`
callable for the scanner, a `fetch` callable for the jurisdiction refresh, an in-memory
storage backend) specifically so the test suite runs without zmap/zgrab2, AWS
credentials, or network access.

## Public site

Served by `ichnos serve` (`webapp/app.py`), same instance/IP that does the scanning:

- `/` - project info, live scan schedule, FAQ.
- `/responsible-scanning` - the page for anyone who's noticed a connection from this
  project: ports/data collected, what's explicitly *not* done, actual scan frequency,
  contact, opt-out, data retention, and a link to ZMap's Scanning Best Practices.
- `/.well-known/security.txt` (and `/security.txt` for tools that check the legacy
  location) - [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
- `/scanner.txt` - informal, not a standard, but common practice among Internet
  measurement projects (Shodan, Censys publish similar).
- `/opt-out` - self-service exclusion, takes effect before the next scheduled scan.

The scanner's Elastic IP also has a reverse-DNS PTR record (`scan.ichnos.online`,
`terraform/dns.tf` + a one-time `aws ec2 modify-address-attribute` call documented in
`terraform/README.md`) rather than a bare AWS hostname - legitimacy signal to
whoever's inspecting probe traffic, per the ZMap best-practices guidance above.

**Not yet built** (deferred, per the same review that prompted the pages above - "as
the project matures," not MVP-blocking): a methodology page covering scan cadence,
randomization strategy, exclusion policy, data quality, false-positive rate, and known
limitations.

## Infrastructure

Terraform for the real deployment (EC2 ASG, DynamoDB tables, S3, Secrets Manager,
Route 53, IAM, CloudWatch) lives in `terraform/` - see `terraform/README.md` for setup
and the deployed layout. Not a design-doc gap anymore; it's live.
