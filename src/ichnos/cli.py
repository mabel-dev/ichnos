"""CLI entrypoints (design doc §5, §14 Phase 3).

Five subcommands, matching the things design doc §4/§5 says run on cron:

    ichnos scan --protocol http --candidates N
        The discovery job (design doc §4): a single long-running ZMap discovery
        process covering up to N candidate addresses, natively rate-limited via
        ZMap's own `--rate` (see scanner.py) rather than externally paced - runs for
        roughly `N / rate_pps` seconds plus a fixed cooldown tail, so size
        `--candidates` to about fill the gap until cron's next invocation. Excludes
        currently-known-responsive hosts from its candidate pool (see
        `_rebuild_blocklist`) - that's `refresh`'s job, not discovery's, so discovery
        spends its budget on addresses that are actually untested or unresponsive.
        Appends results to `pending_dir` as NDJSON, to be picked up by `publish`.

    ichnos refresh --protocol http
        The refresh job: re-tests every currently-known-responsive host for a
        protocol to detect drift (a server upgrade, a cert rotation, a new
        fingerprint) since it was last seen. No ZMap discovery involved - the target
        list is already known, so this goes straight to a ZGrab2 grab per host (see
        `scanner.run_refresh_scan`). Distinct cadence from `scan`: discovery explores
        unknown space and can run continuously; refresh re-checks a small known set
        and is meant to run on a more relaxed schedule (daily, indicatively).

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
import os
import sys
import uuid
import zlib
from datetime import datetime
from datetime import timezone
from typing import Iterable

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
from .odata import ODataError
from .odata import fetch_access_token
from .publish import clear_pending
from .publish import exclusion_rows
from .publish import publish_hour
from .publish import read_pending_datasets
from .responsive import read_responsive_file
from .responsive import read_responsive_hosts
from .responsive import refresh_protocol
from .ratelimit import TokenBucket
from .s3sync import download_file as s3_download_file
from .s3sync import upload_file as s3_upload_file
from .scanner import ScanRunOutcome
from .scanner import run_refresh_scan
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
            version_index_table=settings.version_index_table,
        )
    raise ValueError(f"unknown store backend: {backend!r}")


def _read_jurisdiction_cidrs(path: str) -> list:
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []


def _split_csv(value: str) -> list:
    """Comma-separated env var -> list, dropping blanks so a trailing comma or an
    unset-but-present variable yields [] rather than [""] (which would render as an
    empty bullet on the public page)."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _rebuild_blocklist(settings: Settings, store, *, extra_exclusions: Iterable[str] = ()) -> None:
    """Shared by `scan` and `refresh` - both need the current bogons+exclusions+
    jurisdiction blocklist rebuilt fresh before every run (an opt-out or jurisdiction
    change must take effect on the very next scheduled run of either). `scan` passes
    the currently-known-responsive set as `extra_exclusions` so discovery doesn't keep
    re-finding hosts `refresh` already covers; `refresh` passes none - it must *not*
    exclude the hosts it exists to re-check."""
    if not os.path.exists(settings.jurisdiction_blocklist_path) and settings.jurisdiction_s3_bucket:
        found = s3_download_file(
            settings.jurisdiction_s3_bucket,
            settings.jurisdiction_s3_key,
            settings.jurisdiction_blocklist_path,
        )
        logger.info(
            "no local jurisdiction blocklist - %s from s3://%s/%s",
            "pulled last-known-good copy" if found else "none found either, starting empty",
            settings.jurisdiction_s3_bucket, settings.jurisdiction_s3_key,
        )

    exclusion_entries = [e.ip_or_cidr for e in store.exclusions.list_all()]
    extra_exclusions = list(extra_exclusions)
    jurisdiction_cidrs = _read_jurisdiction_cidrs(settings.jurisdiction_blocklist_path)
    cidrs = build_blocklist(
        exclusion_entries=[*exclusion_entries, *extra_exclusions],
        jurisdiction_cidrs=jurisdiction_cidrs,
    )
    write_blocklist_file(settings.blocklist_path, cidrs)
    logger.info(
        "blocklist rebuilt: %d entries (%d exclusions, %d known-responsive, %d jurisdiction) -> %s",
        len(cidrs), len(exclusion_entries), len(extra_exclusions), len(jurisdiction_cidrs),
        settings.blocklist_path,
    )


def _write_pending_outcome(settings: Settings, outcome: ScanRunOutcome) -> None:
    batch = PublishBatch()
    batch.add_scan_outcome(outcome)
    for dataset, rows in batch.datasets().items():
        append_ndjson(f"{settings.pending_dir}/{dataset}.ndjson", rows)


def cmd_scan(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    store = _build_store(args.store, settings)

    entry = store.schedule.get(args.protocol)
    if entry is None or not entry.enabled:
        logger.error("protocol %r is not an enabled ScanSchedule entry", args.protocol)
        return 1

    # Read from the file responsive-refresh derives nightly, not from a CurrentState
    # scan. This used to be `store.current_state.list_all(protocol)` on every tick -
    # and because the table is keyed by a single partition key, that is a DynamoDB
    # *Scan* with a filter, so it reads every item and discards the two thirds
    # belonging to other protocols (storage/dynamodb.py). Three of those an hour,
    # against a table that grew from 15,199 items to 124,357 in a single day, each one
    # then deserialised into Python objects and collapsed with ~22k jurisdiction CIDRs.
    # That is a per-tick cost that scales with everything discovery has ever found and
    # not at all with what this run is about to do.
    #
    # The file is a 15-day window (responsive.py) rather than the whole history, so it
    # is bounded where CurrentState is not, and it is at most a night stale. That
    # staleness costs almost nothing: a host found after the last rebuild stays in the
    # candidate pool until the next one, and the chance of a random draw landing on any
    # specific address again within a day is around 4 in 10,000.
    #
    # An empty list is wasteful, not unsafe - it means discovery re-finds hosts it
    # already knows. The exclusions and jurisdiction layers, which are the ones that
    # matter for not scanning people who asked not to be, are unaffected and still
    # rebuilt from source on every tick below.
    known_responsive_ips = read_responsive_file(
        settings.known_responsive_path.format(protocol=args.protocol)
    )
    if not known_responsive_ips:
        logger.warning(
            "no known-responsive list for %s - discovery will re-find hosts it already "
            "knows until responsive-refresh next runs",
            args.protocol,
        )
    _rebuild_blocklist(settings, store, extra_exclusions=known_responsive_ips)

    # Real, previously-undetected bug: a seed fixed for the whole calendar day meant
    # ZMap's deterministic address permutation - and therefore the actual candidate
    # set for a given --candidates count - was identical across every cron tick that
    # day. The known-responsive-host exclusion above only removes the tiny fraction
    # that ever answered; the overwhelming majority of each tick's addresses were the
    # exact same never-responsive ones, tick after tick, all day - discovery wasn't
    # actually exploring new address space after the first tick. Seeding from the
    # current timestamp instead gives every invocation its own permutation - confirmed
    # from real data: the worst-offending repeat address (884 observations) stopped
    # recurring entirely once this landed.
    #
    # A second, smaller version of the same bug: cron fires the http/https/ssh scan
    # entries within the same second, and int(...timestamp()) truncates to whole
    # seconds - so every protocol independently computed the *same* seed each tick
    # (confirmed from real logs: identical seed across all three at every timestamp
    # checked). Same permutation means all three protocols tested the same candidate
    # IPs each cycle instead of exploring three independent slices of the address
    # space. A small per-protocol salt (stable regardless of Python's per-process hash
    # randomization, unlike the builtin hash()) keeps each protocol on its own
    # permutation while still giving the same protocol a fresh seed every tick.
    protocol_salt = zlib.crc32(args.protocol.encode()) % 1000
    seed = (
        args.seed if args.seed is not None
        else int(datetime.now(timezone.utc).timestamp()) + protocol_salt
    )
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
        version_index=store.version_index,
        target_ip=args.target,
        gateway_mac=settings.zmap_gateway_mac or None,
        cooldown_seconds=settings.zmap_cooldown_seconds,
        rate_pps=args.rate_pps or settings.zmap_rate_pps,
        grab_concurrency=settings.grab_concurrency,
        user_agent=settings.scan_user_agent,
    )
    _write_pending_outcome(settings, outcome)

    logger.info(
        "scan %s done: %d attempted, %d responsive, %d new fingerprints",
        scan_id, outcome.metadata.targets_attempted, outcome.metadata.hosts_responsive,
        len(outcome.new_versions),
    )
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    store = _build_store(args.store, settings)

    entry = store.schedule.get(args.protocol)
    if entry is None or not entry.enabled:
        logger.error("protocol %r is not an enabled ScanSchedule entry", args.protocol)
        return 1

    _rebuild_blocklist(settings, store)

    # Paced by refresh_rate_per_second, not the MVP rate_interval_seconds bucket -
    # refresh's workload is discovery's output, and discovery has outrun a 5-second
    # interval by two orders of magnitude. See config.py's refresh_rate_per_second.
    rate_limiter = TokenBucket(1.0 / settings.refresh_rate_per_second, burst=1)
    scan_id = f"{args.protocol}-refresh-{uuid.uuid4().hex[:12]}"
    logger.info(
        "refresh %s starting: protocol=%s port=%s rate=%g/s concurrency=%d budget=%gs",
        scan_id, args.protocol, entry.port,
        settings.refresh_rate_per_second, settings.grab_concurrency,
        settings.refresh_duration_seconds,
    )

    outcome = run_refresh_scan(
        scan_id=scan_id,
        protocol=args.protocol,
        port=entry.port,
        zgrab2_module=entry.zgrab2_module,
        blocklist_path=settings.blocklist_path,
        rate_limiter=rate_limiter,
        known_hosts=[ip for ip, _ in read_responsive_hosts(
            settings.known_responsive_path.format(protocol=args.protocol)
        )],
        version_index=store.version_index,
        user_agent=settings.scan_user_agent,
        concurrency=settings.grab_concurrency,
        time_budget_seconds=settings.refresh_duration_seconds or None,
    )
    _write_pending_outcome(settings, outcome)

    logger.info(
        "refresh %s done: %d attempted, %d responsive, %d new fingerprints",
        scan_id, outcome.metadata.targets_attempted, outcome.metadata.hosts_responsive,
        len(outcome.new_versions),
    )
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    datasets = read_pending_datasets(settings.pending_dir)

    if not settings.opteryx_client_id or not settings.opteryx_client_secret:
        logger.error(
            "ICHNOS_OPTERYX_CLIENT_ID / ICHNOS_OPTERYX_CLIENT_SECRET not set - "
            "cannot authenticate to the Opteryx Upload Service"
        )
        return 1

    # Published every cycle regardless of whether any scanning happened, and
    # deliberately not gated on "is there anything pending" the way the scan-produced
    # datasets are. It is committed with OVERWRITE (see publish.OVERWRITE_DATASETS), so
    # skipping a cycle leaves a stale generation published; an opt-out withdrawn during
    # an idle hour has to propagate just as promptly as one withdrawn during a busy one.
    # exclusion_rows() always returns at least the sentinel, so this is never empty.
    store = _build_store(args.store, settings)
    datasets["exclusions"] = exclusion_rows(
        store.exclusions.list_all(),
        jurisdiction_cidrs=_read_jurisdiction_cidrs(settings.jurisdiction_blocklist_path),
    )

    from opteryx_upload import PATAuthenticator
    from opteryx_upload import UploadClient
    from opteryx_upload import UploadClientError

    auth = PATAuthenticator(
        client_id=settings.opteryx_client_id, client_secret=settings.opteryx_client_secret
    )
    client = UploadClient(token=auth)

    def _committed(dataset: str, commit) -> None:
        # Clear this dataset's pending file the moment it lands, rather than clearing
        # the whole batch after the loop. A dataset that failed still holds its file for
        # the next cycle's retry; one that already committed must not be sent twice.
        logger.info("%s: commit %s, %s rows", dataset, commit.commit_id, commit.rows_written)
        clear_pending(settings.pending_dir, [dataset])

    try:
        publish_hour(
            client,
            datasets,
            workspace=settings.opteryx_workspace,
            collection=settings.opteryx_collection,
            tmp_dir=settings.publish_tmp_dir,
            on_commit=_committed,
        )
    except PublishError as exc:
        logger.error("publish failed, leaving pending files in place for retry: %s", exc)
        return 1
    except UploadClientError as exc:
        # Covers everything else the Upload Service can reject a commit for (auth,
        # authorization, conflicts, size limits, its own transient failures) - all of
        # them get the same treatment as PublishError above: log it, leave the pending
        # files in place, let the next hourly cron retry rather than crash with a raw
        # traceback and silently lose nothing (files are untouched either way) but say
        # nothing useful about what happened.
        logger.error(
            "publish failed (%s), leaving pending files in place for retry: %s",
            type(exc).__name__, exc,
        )
        return 1

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

    if settings.jurisdiction_s3_bucket:
        s3_upload_file(
            settings.jurisdiction_s3_bucket,
            settings.jurisdiction_s3_key,
            settings.jurisdiction_blocklist_path,
        )
        logger.info(
            "uploaded to s3://%s/%s for the next instance to pull at startup",
            settings.jurisdiction_s3_bucket, settings.jurisdiction_s3_key,
        )
    return 0


def cmd_responsive_refresh(args: argparse.Namespace) -> int:
    """Rebuild the known-responsive host list from published Observations.

    Nightly, ahead of `refresh`, and at boot - the file lives on the instance's root
    volume, which does not survive a replacement, and both consumers read it from
    there. Discovery uses it as the known-responsive exclusion; refresh uses it as its
    target list, oldest-checked first.

    It ran in parallel with CurrentState first, logging how the two compared: across
    all three protocols the derived list contained nothing the table did not, which is
    what justified dropping the table.
    """
    settings = Settings.from_env()
    if not settings.opteryx_client_id or not settings.opteryx_client_secret:
        logger.error(
            "ICHNOS_OPTERYX_CLIENT_ID / ICHNOS_OPTERYX_CLIENT_SECRET not set - "
            "cannot authenticate to the OData feed"
        )
        return 1

    try:
        token = fetch_access_token(
            settings.opteryx_client_id,
            settings.opteryx_client_secret,
            token_url=settings.odata_token_url,
        )
    except ODataError as exc:
        # Every protocol shares the token, so this is fatal for the whole run - but
        # it leaves every existing list in place, which is the safe outcome.
        logger.error("responsive-refresh: could not obtain an access token: %s", exc)
        return 1

    store = _build_store(args.store, settings)
    # list_enabled, not list_all - ScheduleStore has no list_all, and a disabled
    # protocol should not get a list built for it anyway.
    protocols = [args.protocol] if args.protocol else [
        e.protocol for e in store.schedule.list_enabled()
    ]

    failures = 0
    for protocol in protocols:
        path = settings.known_responsive_path.format(protocol=protocol)
        ok = refresh_protocol(
            protocol,
            path,
            workspace=settings.opteryx_workspace,
            collection=settings.opteryx_collection,
            token=token,
            window_days=settings.responsive_window_days,
            base_url=settings.odata_base_url,
        )
        if not ok:
            failures += 1
            continue

    return 1 if failures else 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = Settings.from_env()
    store = _build_store(args.store, settings)
    site_config = SiteConfig(
        organisation=settings.site_organisation,
        contact_email=settings.site_contact_email,
        form_secret=settings.site_form_secret,
        site_url=settings.site_url,
        trust_proxy_headers=settings.trust_proxy_headers,
        scan_hostname=settings.site_scan_hostname,
        scan_source_ips=_split_csv(settings.site_scan_source_ips),
        scan_user_agent=settings.scan_user_agent,
    )
    app = create_app(store, site_config)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ichnos")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run one throttled scan for a protocol")
    scan.add_argument("--protocol", required=True)
    scan.add_argument("--candidates", type=int, default=12)
    scan.add_argument(
        "--rate-pps",
        type=int,
        default=None,
        dest="rate_pps",
        help=(
            "ZMap --rate for this run, overriding ICHNOS_ZMAP_RATE_PPS. Set per "
            "protocol by cron, because the protocols do not cost the same: a run's "
            "grab load is candidates x hit rate, and the measured hit rates differ by "
            "more than 2x (https 1.71%%, http 1.52%%, ssh 0.77%%), so an equal "
            "candidate count means unequal work. Sizing candidates and rate together "
            "per protocol keeps every run inside the same hourly window."
        ),
    )
    scan.add_argument("--seed", type=int, default=None)
    scan.add_argument(
        "--target",
        default=None,
        help=(
            "scan this specific IP instead of random candidates (still blocklist-"
            "checked) - for verifying the pipeline against a known-responsive host"
        ),
    )
    scan.add_argument("--store", choices=["dynamodb", "memory"], default="dynamodb")
    scan.set_defaults(func=cmd_scan)

    refresh = subparsers.add_parser(
        "refresh", help="re-test every currently-known-responsive host for a protocol"
    )
    refresh.add_argument("--protocol", required=True)
    refresh.add_argument("--store", choices=["dynamodb", "memory"], default="dynamodb")
    refresh.set_defaults(func=cmd_refresh)

    publish = subparsers.add_parser("publish", help="commit pending rows to Opteryx")
    # Needed since the batch now includes an `exclusions` snapshot read from the store,
    # not just the scan-produced rows accumulated in pending_dir.
    publish.add_argument("--store", choices=["dynamodb", "memory"], default="dynamodb")
    publish.set_defaults(func=cmd_publish)

    rrefresh = subparsers.add_parser(
        "responsive-refresh",
        help="rebuild the known-responsive host list from published Observations",
    )
    rrefresh.add_argument("--protocol", default=None, help="default: every scheduled protocol")
    rrefresh.add_argument("--store", choices=["dynamodb", "memory"], default="dynamodb")
    rrefresh.set_defaults(func=cmd_responsive_refresh)

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
