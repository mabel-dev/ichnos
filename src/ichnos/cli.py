"""CLI entrypoints (design doc §5, §14 Phase 3).

Four subcommands, matching the four things design doc §4/§5 says run on cron:

    ichnos scan --protocol http --candidates N
        One throttled scan run (design doc §4). Runs for roughly
        `candidates * rate_interval_seconds * 2` seconds (each candidate can consume up
        to two rate-limiter tokens - one ZMap probe, one ZGrab2 grab - see scanner.py),
        so size `--candidates` to about fill the gap until cron's next invocation
        rather than invoking this once per candidate. Appends results to
        `pending_dir` as NDJSON, to be picked up by `publish`.

    ichnos publish
        The hourly batch job (design doc §3.2): reads everything in `pending_dir`,
        commits it to Opteryx via `opteryx-upload`, and clears the pending files only
        on success.

    ichnos jurisdiction-refresh
        The weekly job (design doc §3.1.1) that rebuilds the JP/KP/KR/CN/RU/IR
        pre-exclusion CIDR list.

    ichnos serve
        Runs the public info page + opt-out webapp (design doc §6).

Storage backend defaults to DynamoDB (the real deployment target) but can be forced to
an in-memory store with `--store memory` for local dry runs - that mode does not
persist between invocations and is not meant for anything beyond a demo.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from datetime import date

from .blocklist import build_blocklist
from .blocklist import write_blocklist_file
from .config import Settings
from .jurisdiction import DEFAULT_COUNTRIES
from .jurisdiction import refresh_jurisdiction_blocklist
from .logging_setup import configure_logging
from .logging_setup import get_logger
from .publish import PublishBatch
from .publish import PublishError
from .publish import append_ndjson
from .publish import clear_pending
from .publish import publish_hour
from .publish import read_pending_datasets
from .ratelimit import TokenBucket
from .scanner import run_scan
from .storage.memory import InMemoryStore
from .webapp import SiteConfig
from .webapp import create_app

logger = get_logger(__name__)


def _build_store(backend: str, settings: Settings):
    if backend == "memory":
        return InMemoryStore()
    if backend == "dynamodb":
        from .storage.dynamodb import DynamoDBStore

        return DynamoDBStore(
            exclusions_table=settings.exclusions_table,
            schedule_table=settings.schedule_table,
            scan_metadata_table=settings.scan_metadata_table,
            current_state_table=settings.current_state_table,
        )
    raise ValueError(f"unknown store backend: {backend!r}")


def _read_jurisdiction_cidrs(path: str) -> list:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []


def cmd_scan(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    store = _build_store(args.store, settings)

    entry = store.schedule.get(args.protocol)
    if entry is None or not entry.enabled:
        logger.error("protocol %r is not an enabled ScanSchedule entry", args.protocol)
        return 1

    exclusion_entries = [e.ip_or_cidr for e in store.exclusions.list_all()]
    jurisdiction_cidrs = _read_jurisdiction_cidrs(settings.jurisdiction_blocklist_path)
    cidrs = build_blocklist(
        exclusion_entries=exclusion_entries, jurisdiction_cidrs=jurisdiction_cidrs
    )
    write_blocklist_file(settings.blocklist_path, cidrs)
    logger.info(
        "blocklist rebuilt: %d entries (%d exclusions, %d jurisdiction) -> %s",
        len(cidrs), len(exclusion_entries), len(jurisdiction_cidrs), settings.blocklist_path,
    )

    seed = args.seed if args.seed is not None else int(date.today().strftime("%Y%m%d"))
    rate_limiter = TokenBucket(settings.rate_interval_seconds, burst=1)
    scan_id = f"{args.protocol}-{uuid.uuid4().hex[:12]}"
    logger.info(
        "scan %s starting: protocol=%s port=%s candidates=%d seed=%d",
        scan_id, args.protocol, entry.port, args.candidates, seed,
    )

    outcome = run_scan(
        scan_id=scan_id,
        protocol=args.protocol,
        port=entry.port,
        zgrab2_module=entry.zgrab2_module,
        seed=seed,
        candidate_count=args.candidates,
        blocklist_path=settings.blocklist_path,
        rate_limiter=rate_limiter,
        current_state=store.current_state,
    )
    store.scan_metadata.put(outcome.metadata)

    batch = PublishBatch()
    batch.add_scan_outcome(outcome)
    for dataset, rows in batch.datasets().items():
        append_ndjson(f"{settings.pending_dir}/{dataset}.ndjson", rows)

    logger.info(
        "scan %s done: %d attempted, %d responsive, %d new fingerprints",
        scan_id, outcome.metadata.targets_attempted, outcome.metadata.hosts_responsive,
        len(outcome.new_versions),
    )
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    datasets = read_pending_datasets(settings.pending_dir)
    if not datasets:
        logger.info("nothing pending to publish")
        return 0

    if not settings.opteryx_client_id or not settings.opteryx_client_secret:
        logger.error(
            "ICHNOS_OPTERYX_CLIENT_ID / ICHNOS_OPTERYX_CLIENT_SECRET not set - "
            "cannot authenticate to the Opteryx Upload Service"
        )
        return 1

    from opteryx_upload import PATAuthenticator
    from opteryx_upload import UploadClient

    auth = PATAuthenticator(
        client_id=settings.opteryx_client_id, client_secret=settings.opteryx_client_secret
    )
    client = UploadClient(token=auth)

    try:
        results = publish_hour(
            client,
            datasets,
            workspace=settings.opteryx_workspace,
            collection=settings.opteryx_collection,
            tmp_dir=settings.publish_tmp_dir,
        )
    except PublishError as exc:
        logger.error("publish failed, leaving pending files in place for retry: %s", exc)
        return 1

    clear_pending(settings.pending_dir, list(datasets.keys()))
    for dataset, commit in results.items():
        logger.info("%s: commit %s, %s rows", dataset, commit.commit_id, commit.rows_written)
    return 0


def cmd_jurisdiction_refresh(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    countries = tuple(args.countries.split(",")) if args.countries else DEFAULT_COUNTRIES
    logger.info("fetching jurisdiction blocklist from %s for %s", args.source, countries)
    result = refresh_jurisdiction_blocklist(countries, source=args.source)
    write_blocklist_file(settings.jurisdiction_blocklist_path, result.cidrs)
    logger.info(
        "jurisdiction blocklist refreshed from %s: %d CIDRs for %s -> %s",
        result.source, result.count, ", ".join(result.countries),
        settings.jurisdiction_blocklist_path,
    )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = Settings.from_env()
    store = _build_store(args.store, settings)
    site_config = SiteConfig()
    app = create_app(store, site_config)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ichnos")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run one throttled scan for a protocol")
    scan.add_argument("--protocol", required=True)
    scan.add_argument("--candidates", type=int, default=12)
    scan.add_argument("--seed", type=int, default=None)
    scan.add_argument("--store", choices=["dynamodb", "memory"], default="dynamodb")
    scan.set_defaults(func=cmd_scan)

    publish = subparsers.add_parser("publish", help="commit pending rows to Opteryx")
    publish.set_defaults(func=cmd_publish)

    jrefresh = subparsers.add_parser(
        "jurisdiction-refresh", help="rebuild the jurisdiction pre-exclusion CIDR list"
    )
    jrefresh.add_argument("--source", choices=["rir", "ipdeny"], default="rir")
    jrefresh.add_argument("--countries", default=None, help="comma-separated ISO country codes")
    jrefresh.set_defaults(func=cmd_jurisdiction_refresh)

    serve = subparsers.add_parser("serve", help="run the public info page + opt-out webapp")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--store", choices=["dynamodb", "memory"], default="dynamodb")
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv=None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
