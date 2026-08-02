# ichnos

Internet measurement service: ZMap discovers responsive hosts, ZGrab2 fingerprints
them, and results are batched hourly into [Opteryx](https://opteryx.app) via the public
`opteryx-upload` client. Full design rationale lives in the
[`scan.opteryx`](../scan.opteryx/DESIGN.md) design document - this repo is the
implementation of that design's Phase 3 (HTTP/HTTPS-only MVP).

## Scope (MVP)

- **Protocols**: HTTP and HTTPS only.
- **Rate**: no more than one outbound request per 5 seconds, as a single budget shared
  across both protocols (see `ratelimit.py`).
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
  models.py          # Exclusion, ScheduleEntry, ScanMetadataRecord, CurrentStateRecord, ...
  storage/            # storage interfaces + in-memory (dev) and DynamoDB (real) backends
  ratelimit.py        # global token-bucket throttle
  blocklist.py        # merges bogons + self-serve opt-outs + jurisdiction CIDRs
  jurisdiction.py      # weekly job: RIR delegated-stats (or ipdeny fallback) -> CIDR list
  normalize.py         # extracts protocol-relevant fields from raw ZGrab2 JSON
  fingerprint.py        # canonicalize + hash normalized fields -> fingerprint_id
  scanner.py            # zmap/zgrab2 subprocess orchestration, paced by the rate limiter
  publish.py             # batches changed rows and commits to Opteryx via opteryx-upload
  webapp/                # public info page + self-service opt-out (FastAPI)
  cli.py                 # `ichnos scan|refresh|publish|jurisdiction-refresh|serve`
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
# Rebuild blocklist, run a throttled scan, stage results locally:
ichnos scan --protocol http --candidates 12 --store memory

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

See `cli.py`'s module docstring for how `--candidates` relates to the rate limiter and
cron's invocation interval - sizing it wrong either idles the throttle or lets a run
overrun into the next cron tick.

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

## Not yet in this repo

Infrastructure (Terraform/CDK for the EC2 ASG, DynamoDB tables, Secrets Manager, Route
53/PTR, security groups) is design doc Phase 1 and hasn't been written yet - this repo
is the application code that infrastructure would run. See the design doc's
implementation plan for the full phase breakdown.
