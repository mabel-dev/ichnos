# ichnos

Internet measurement service: ZMap discovers responsive hosts, ZGrab2 fingerprints
them, and results are batched hourly into [Opteryx](https://opteryx.app) via the public
`opteryx-upload` client. This repo is the implementation of a private design doc's
Phase 3 (HTTP/HTTPS-only MVP) - the design doc itself isn't published in this repo.

**Live site:** <https://ichnos.online> (see [`/responsible-scanning`](https://ichnos.online/responsible-scanning)
if you've noticed a connection from this project) &middot; **Abuse contact:**
[abuse@opteryx.app](mailto:abuse@opteryx.app)

This project follows [ZMap's Scanning Best
Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices) for rate
limiting, target selection, and exclusion handling, and [AWS's guidelines for network
scanning](https://repost.aws/articles/ARCz_zlQsaSemhaszZ5--YlA/aws-guidelines-for-network-scanning)
for being observable, identifiable, and cooperative - see [Scanner
identity](#scanner-identity) below.

## Scope (MVP)

- **Protocols**: HTTP, HTTPS, and SSH.
- **Discovery vs refresh**: `scan` runs native ZMap discovery (rate-limited via ZMap's
  own `--rate`, `ICHNOS_ZMAP_RATE_PPS` - 32 pps as of the latest adjustment, see
  `config.py`'s `zmap_rate_pps`) over addresses that aren't already known-responsive,
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
Internet coverage. Rate and protocol count have both grown incrementally since MVP
launch, each backed by observed production data (see git history on `config.py` and
`normalize.py`) rather than upfront guessing - the current 8 pps step went out ahead of
its observation window, which was then run immediately afterwards to confirm it (7h45m,
93 runs, no skipped ticks; see `config.py`'s `zmap_rate_pps`). Distributing across
workers is still
explicitly deferred - see the design doc's scaling strategy.

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
full list (table names, blocklist paths, rate interval, discovery rate,
Opteryx workspace/collection, PAT credentials). Nothing is hardcoded so schedule/rate/
target changes don't need a redeploy, per the design doc's operational model - though
that only holds for settings the instance's `/etc/ichnos/env` actually writes out
(`user_data.sh.tftpl`). `ICHNOS_ZMAP_RATE_PPS` was the exception until it was added
there: it was env-readable in `config.py` but never set, so changing the discovery rate
meant reinstalling the package. Adding a setting to `config.py` alone is half the job.

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

## Scanner identity

Probe traffic is attributable back to this project without the recipient having to
guess, per AWS's network-scanning guidelines ("the scanner is identifiable"):

- **User-Agent** - HTTP grabs carry `ichnos/1.0 (+<site>/responsible-scanning; opt-out
  <site>/opt-out)` (`ICHNOS_SCAN_USER_AGENT`), so the opt-out route is visible in the
  target's own access log rather than only to someone who thinks to do a reverse
  lookup. ZGrab2's default is a generic scanner string. Applies to the **http module
  only** - HTTPS is grabbed via the `tls` module, which sends no HTTP request, and
  `--user-agent` is not a valid flag there (see `scanner.py`'s `grab_one`).
- **Source address** - the scanner's Elastic IP and its `scan.<domain>` hostname are
  published on `/responsible-scanning` and in `/scanner.txt`
  (`ICHNOS_SITE_SCAN_SOURCE_IPS` / `ICHNOS_SITE_SCAN_HOSTNAME`, both templated from
  the EIP by `terraform/user_data.sh.tftpl`, since the repo doesn't know the address).

Not adopted: the guidelines also ask scanners to respect targets' `robots.txt`. This
project doesn't fetch it - doing so would double the request count per target to obey a
file that governs content crawling, while ichnos records only status code, headers, and
`<title>` from a single handshake. That's a deliberate position, not an oversight; the
deferred methodology page below is where it should be stated publicly.

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
