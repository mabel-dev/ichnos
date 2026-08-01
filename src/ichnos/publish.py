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
from typing import Dict
from typing import List

from opteryx_upload import CommitResult
from opteryx_upload import ConflictResolution
from opteryx_upload import Target
from opteryx_upload import UploadClient

from .parquet import convert_to_parquet
from .scanner import ScanRunOutcome


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
    candidates: List[Dict] = field(default_factory=list)

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
        self.candidates.extend(c.as_dict() for c in outcome.candidates)

    def is_empty(self) -> bool:
        return not (
            self.observations
            or self.versions
            or any(self.protocol_rows.values())
            or self.scan_metadata
            or self.candidates
        )

    def datasets(self) -> Dict[str, List[Dict]]:
        result = {
            "observations": self.observations,
            "versions": self.versions,
            "scan_metadata": self.scan_metadata,
            "candidates": self.candidates,
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
    """Remove pending files for datasets that were just committed successfully. Only
    call this after `publish_hour` returns without raising - see module docstring on
    why a failed batch should hold its files rather than lose them."""
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
) -> Dict[str, CommitResult]:
    """Commit every non-empty dataset. Raises `PublishError` on the first dataset the
    Upload Service flags via `inspect()` - callers should treat any exception here as
    "nothing after this dataset was committed, retry the whole hour next cycle" rather
    than trying to resume mid-batch."""
    os.makedirs(tmp_dir, exist_ok=True)
    results: Dict[str, CommitResult] = {}

    for dataset, rows in datasets.items():
        if not rows:
            continue
        ndjson_path = os.path.join(tmp_dir, f"{dataset}.ndjson")
        write_ndjson(ndjson_path, rows)
        parquet_path = os.path.join(tmp_dir, f"{dataset}.parquet")
        convert(ndjson_path, parquet_path)

        session = client.create_session()
        session.upload_file(parquet_path)
        inspect_result = session.inspect()
        if inspect_result is not None and inspect_result.has_issues:
            raise PublishError(dataset, inspect_result.issues)

        commit = session.commit(
            Target(workspace, collection, dataset),
            snapshot_message=f"ichnos hourly batch {datetime.now(timezone.utc).isoformat()}",
            conflict_resolution=ConflictResolution.APPEND,
        )
        results[dataset] = commit

    return results
