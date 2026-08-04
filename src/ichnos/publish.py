"""Hourly batch publish to Opteryx via the `opteryx-upload` public API (design doc §3.2).

The worker never touches Opteryx internals - it only calls the same Upload Service
surface any external Opteryx customer uses: create a session, stage a part,
`inspect()`, then `commit(conflict_resolution=APPEND)`. Rows are staged as NDJSON
locally (simple to append to incrementally, see `append_ndjson`) but converted to
Parquet via `rugo` (parquet.py) before upload - Opteryx is a relational, Parquet-backed
engine, and Parquet is the documented, recommended format for regular batch loads, not
just NDJSON's convenience-path auto-splitting. At MVP volume (throttled to ~1
request/5s, design doc §4) a batch is at most a few hundred rows per dataset either way.

Failure handling is the caller's responsibility, deliberately: `publish_hour` raises on
the first failed dataset rather than partially committing and swallowing the rest, and
does not delete the NDJSON files it wrote. Per design doc §12, a failed hourly batch
should hold its local files and retry on the next cycle rather than drop data - that
retry/hold decision belongs in the CLI/cron layer, not buried in this module.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional

from opteryx_upload import CommitResult
from opteryx_upload import ConflictResolution
from opteryx_upload import Target
from opteryx_upload import UploadClient

from .parquet import convert_to_parquet
from .scanner import ScanRunOutcome

# Explicit Parquet schema per dataset - real, previously-undetected production
# incident, not a defensive-programming exercise: without this, rugo infers each
# batch's column types from that batch's own rows, and Opteryx pins a table's schema
# from whichever batch happens to create it. A column that's all-null in the founding
# batch (e.g. redirect_location, when no scan in that batch hit a redirect) gets
# inferred as a void/null type - every later batch with a real value for that column
# then gets rejected outright ("table structure doesn't match"), which repeatedly
# blocked the `http` dataset's hourly publish. Declaring every column's type here,
# once, means every batch (including the very first) produces an identical schema
# regardless of what values happen to be in it - confirmed directly against the real
# rugo binary: an explicit-schema column that's all-null in the data still comes out
# typed VARCHAR, not void. Any dataset not listed here falls back to rugo's own
# per-batch inference (see parquet.convert_to_parquet).
#
# Every instant is declared "timestamp", not "string" - parquet.py turns those into
# real TIMESTAMP64 columns (see its module docstring). They were all VARCHAR until
# then: ISO-8601 text that reads like a timestamp in a query result but sorts, ranges
# and windows as a string. `headers`/`certificate`/`payload` stay "string" despite
# each holding a JSON document, because there is nothing else to declare them as -
# draken has NVARCHAR and VARIANT types, but neither survives a Parquet round-trip
# (rugo's writer emits byte_array/varchar for all three, and its reader tags them all
# back as VARCHAR), so a JSON-typed column isn't expressible through the upload path.
SCHEMAS: Dict[str, Dict[str, str]] = {
    "observations": {
        "scan_id": "string",
        "observed_at": "timestamp",
        "ip": "string",
        "port": "int64",
        "protocol": "string",
        "response_status": "string",
        "fingerprint_id": "string",
    },
    "scan_metadata": {
        "scan_id": "string",
        "protocol": "string",
        "started_at": "timestamp",
        "ended_at": "timestamp",
        "targets_attempted": "int64",
        "hosts_responsive": "int64",
        "status": "string",
        "seed": "int64",
    },
    "versions": {
        "fingerprint_id": "string",
        "protocol": "string",
        "first_seen": "timestamp",
        "payload": "string",
    },
    "exclusions": {
        "ip_or_cidr": "string",
        "source": "string",
        "requested_at": "timestamp",
        "reason": "string",
        "requester_ip": "string",
    },
    "http": {
        "status_code": "int64",
        "headers": "string",
        "server": "string",
        "title": "string",
        "redirect_location": "string",
        "fingerprint_id": "string",
        "first_seen": "timestamp",
    },
    "https": {
        "version": "string",
        "cipher_suite": "string",
        "certificate": "string",
        "fingerprint_id": "string",
        "first_seen": "timestamp",
    },
    "ssh": {
        "banner": "string",
        "version": "string",
        "software": "string",
        "comment": "string",
        "host_key_algorithm": "string",
        "host_key_fingerprint_sha256": "string",
        "fingerprint_id": "string",
        "first_seen": "timestamp",
    },
}


# Every other dataset is an append-only log of things that happened. `exclusions` is
# the opposite: a snapshot of a mutable table, where the interesting event is often a
# *removal* (an opt-out withdrawn, a bad entry deleted). Appending snapshots would make
# the dataset a pile of overlapping generations with no way to tell which is current,
# so this one is committed with OVERWRITE - the published copy is always exactly what
# the Exclusions table holds right now.
OVERWRITE_DATASETS = frozenset({"exclusions"})

# OVERWRITE only takes effect when there is something to commit, and `datasets()` /
# `read_pending_datasets()` both drop empty row lists - so an exclusions list that
# emptied out would publish nothing at all and silently leave the previous generation
# standing in Opteryx, which is the exact failure OVERWRITE exists to prevent. This
# fixed row guarantees the snapshot is never empty, so "all exclusions removed" still
# propagates as a real commit.
#
# 0.0.0.0 is the right choice for that because it changes nothing: 0.0.0.0/8 is already
# in blocklist.DEFAULT_BOGONS ("this host on this network"), and build_blocklist's
# collapse_addresses absorbs the /32 into that /8, so this row cannot alter the
# blocklist by a single byte. A fixed timestamp, not utcnow(), so republishing an
# unchanged table produces an identical snapshot rather than a spurious diff.
SENTINEL_EXCLUSION = {
    "ip_or_cidr": "0.0.0.0",
    "source": "manual",
    "requested_at": datetime(1970, 1, 1, tzinfo=timezone.utc).isoformat(),
    "reason": "fixed sentinel - keeps the exclusions snapshot non-empty so OVERWRITE always commits",
    "requester_ip": None,
}


def exclusion_rows(exclusions) -> List[Dict]:
    """Build the `exclusions` dataset: the current table contents plus the sentinel.

    Takes `Exclusion` records (models.Exclusion) rather than reading the store itself -
    publish.py has no storage dependency and shouldn't grow one.
    """
    rows = [dict(SENTINEL_EXCLUSION)]
    for exclusion in exclusions:
        rows.append(
            {
                "ip_or_cidr": exclusion.ip_or_cidr,
                # `source` is an ExclusionSource (a str Enum) - str() would render it
                # as "ExclusionSource.SELF_SERVE", so take .value explicitly.
                "source": exclusion.source.value,
                "requested_at": exclusion.requested_at.isoformat(),
                "reason": exclusion.reason,
                "requester_ip": exclusion.requester_ip,
            }
        )
    return rows


class PublishError(Exception):
    def __init__(self, dataset: str, issues) -> None:
        self.dataset = dataset
        self.issues = issues
        super().__init__(f"upload service reported issues for dataset {dataset!r}: {issues}")


def _scan_metadata_dict(record) -> Dict:
    return {
        "scan_id": record.scan_id,
        "protocol": record.protocol,
        "started_at": record.started_at.isoformat(),
        "ended_at": record.ended_at.isoformat() if record.ended_at else None,
        "targets_attempted": record.targets_attempted,
        "hosts_responsive": record.hosts_responsive,
        "status": record.status,
        "seed": record.seed,
    }


@dataclass
class PublishBatch:
    """Accumulates rows across however many scan runs happen within an hour, grouped
    by the Opteryx dataset they'll be committed to."""

    observations: List[Dict] = field(default_factory=list)
    versions: List[Dict] = field(default_factory=list)
    protocol_rows: Dict[str, List[Dict]] = field(default_factory=dict)
    scan_metadata: List[Dict] = field(default_factory=list)

    def add_scan_outcome(self, outcome: ScanRunOutcome) -> None:
        self.observations.extend(o.as_dict() for o in outcome.observations)
        for protocol, version in outcome.new_versions:
            self.versions.append(version.as_dict())
            self.protocol_rows.setdefault(protocol, []).append(
                {
                    **version.payload,
                    "fingerprint_id": version.fingerprint_id,
                    "first_seen": version.first_seen.isoformat(),
                }
            )
        self.scan_metadata.append(_scan_metadata_dict(outcome.metadata))

    def is_empty(self) -> bool:
        return not (
            self.observations
            or self.versions
            or any(self.protocol_rows.values())
            or self.scan_metadata
        )

    def datasets(self) -> Dict[str, List[Dict]]:
        result = {
            "observations": self.observations,
            "versions": self.versions,
            "scan_metadata": self.scan_metadata,
        }
        result.update(self.protocol_rows)
        return {name: rows for name, rows in result.items() if rows}


def write_ndjson(path: str, rows: List[Dict]) -> None:
    with open(path, "w") as f:
        for row in rows:
            f.write(json.dumps(row, default=str) + "\n")


def append_ndjson(path: str, rows: List[Dict]) -> None:
    """Append-mode counterpart to `write_ndjson` - what the `scan` CLI command uses to
    accrue rows into `pending_dir` between hourly `publish` runs (cron invokes `scan`
    and `publish` as separate short-lived processes, so the pending rows have to live
    on disk between them, not just in memory)."""
    if not rows:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        for row in rows:
            f.write(json.dumps(row, default=str) + "\n")


def read_pending_datasets(pending_dir: str) -> Dict[str, List[Dict]]:
    """Read back every `*.ndjson` file in `pending_dir` as dataset -> rows. Missing
    directory reads as "nothing pending" rather than an error - the common case right
    after a fresh deployment."""
    if not os.path.isdir(pending_dir):
        return {}
    datasets: Dict[str, List[Dict]] = {}
    for name in sorted(os.listdir(pending_dir)):
        if not name.endswith(".ndjson"):
            continue
        path = os.path.join(pending_dir, name)
        rows = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        if rows:
            datasets[name[: -len(".ndjson")]] = rows
    return datasets


def clear_pending(pending_dir: str, dataset_names: List[str]) -> None:
    """Remove pending files for datasets that have been committed successfully.

    Call this per dataset as each one lands (`publish_hour`'s `on_commit` hook), not
    once for the whole batch at the end. `publish_hour` commits datasets one at a time
    and raises on the first failure, so a mid-loop failure leaves the datasets *before*
    it already committed - clearing only on full success meant those committed rows sat
    in `pending_dir` and were committed a second time by the next cycle's retry. The
    module docstring's "hold the files and retry" rule is about not *losing* data on
    failure; it was never meant to republish what already landed."""
    for name in dataset_names:
        path = os.path.join(pending_dir, f"{name}.ndjson")
        if os.path.exists(path):
            os.remove(path)


def publish_hour(
    client: UploadClient,
    datasets: Dict[str, List[Dict]],
    *,
    workspace: str,
    collection: str,
    tmp_dir: str,
    convert=convert_to_parquet,
    on_commit: Optional[Callable[[str, CommitResult], None]] = None,
) -> Dict[str, CommitResult]:
    """Commit every non-empty dataset. Raises `PublishError` on the first dataset the
    Upload Service flags via `inspect()`.

    `on_commit(dataset, result)` fires immediately after each dataset commits, before
    the next one is attempted - that's how a caller learns which datasets landed when a
    later one raises. Without it the only signal was the return value, which never
    arrives on the failure path, so a caller had no way to distinguish "committed" from
    "not committed" among the datasets of a partially-failed batch (see `clear_pending`
    on what that cost)."""
    os.makedirs(tmp_dir, exist_ok=True)
    results: Dict[str, CommitResult] = {}

    for dataset, rows in datasets.items():
        if not rows:
            continue
        ndjson_path = os.path.join(tmp_dir, f"{dataset}.ndjson")
        write_ndjson(ndjson_path, rows)
        parquet_path = os.path.join(tmp_dir, f"{dataset}.parquet")
        convert(ndjson_path, parquet_path, schema=SCHEMAS.get(dataset))

        session = client.create_session()
        session.upload_file(parquet_path)
        inspect_result = session.inspect()
        if inspect_result is not None and inspect_result.has_issues:
            raise PublishError(dataset, inspect_result.issues)

        resolution = (
            ConflictResolution.OVERWRITE
            if dataset in OVERWRITE_DATASETS
            else ConflictResolution.APPEND
        )
        commit = session.commit(
            Target(workspace, collection, dataset),
            snapshot_message=f"ichnos hourly batch {datetime.now(timezone.utc).isoformat()}",
            conflict_resolution=resolution,
        )
        results[dataset] = commit
        if on_commit is not None:
            on_commit(dataset, commit)

    return results
