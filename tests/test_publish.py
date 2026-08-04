import os
import tempfile
from datetime import datetime
from datetime import timezone
from types import SimpleNamespace

from opteryx_upload import ConflictResolution

from ichnos.blocklist import build_blocklist
from ichnos.models import Exclusion
from ichnos.models import ExclusionSource
from ichnos.models import Observation
from ichnos.models import ScanMetadataRecord
from ichnos.publish import SENTINEL_EXCLUSION
from ichnos.publish import PublishBatch
from ichnos.publish import PublishError
from ichnos.publish import append_ndjson
from ichnos.publish import clear_pending
from ichnos.publish import exclusion_rows
from ichnos.publish import publish_hour
from ichnos.publish import read_pending_datasets
from ichnos.scanner import ScanRunOutcome


def fake_convert(ndjson_path, parquet_path, schema=None):
    """Stand-in for rugo - the real binary isn't available in the test environment,
    and these tests care about the upload/commit flow, not the conversion itself."""
    with open(parquet_path, "w") as f:
        f.write("")


class FakeSession:
    def __init__(self, fail_dataset=None):
        self.uploaded = []
        self.committed_target = None
        self.conflict_resolutions = {}
        self._fail_dataset = fail_dataset

    def upload_file(self, path):
        self.uploaded.append(path)

    def inspect(self):
        if self._fail_dataset and self._fail_dataset in self.uploaded[-1]:
            return SimpleNamespace(has_issues=True, issues=["bad schema"])
        return SimpleNamespace(has_issues=False, issues=[])

    def commit(self, target, *, snapshot_message=None, conflict_resolution=None):
        # Recorded rather than asserted: it is APPEND for every dataset except
        # `exclusions`, which is a snapshot and commits with OVERWRITE.
        self.conflict_resolutions[target.dataset] = conflict_resolution
        self.committed_target = target
        return SimpleNamespace(
            table=target.dataset, commit_id="c1", rows_written=len(self.uploaded), files_created=1
        )


class FakeClient:
    def __init__(self, fail_dataset=None):
        self.sessions = []
        self._fail_dataset = fail_dataset

    def create_session(self):
        session = FakeSession(fail_dataset=self._fail_dataset)
        self.sessions.append(session)
        return session


def test_publish_batch_includes_observations_and_scan_metadata():
    outcome = ScanRunOutcome(
        metadata=ScanMetadataRecord(
            scan_id="s1", protocol="http", started_at=datetime.now(timezone.utc),
            targets_attempted=5, hosts_responsive=1,
        ),
        observations=[
            Observation(
                scan_id="s1", observed_at=datetime.now(timezone.utc), ip="203.0.113.5",
                port=80, protocol="http", response_status="success", fingerprint_id="abc",
            ),
            Observation(
                scan_id="s1", observed_at=datetime.now(timezone.utc), ip="203.0.113.9",
                port=80, protocol="http", response_status="closed", fingerprint_id=None,
            ),
        ],
    )
    batch = PublishBatch()
    batch.add_scan_outcome(outcome)

    datasets = batch.datasets()
    assert "candidates" not in datasets  # dropped: aggregate-only tracking now
    assert len(datasets["observations"]) == 2
    assert {row["ip"] for row in datasets["observations"]} == {"203.0.113.5", "203.0.113.9"}
    assert len(datasets["scan_metadata"]) == 1
    assert not batch.is_empty()


def test_publish_hour_commits_every_nonempty_dataset(tmp_path):
    client = FakeClient()
    datasets = {
        "observations": [{"ip": "1.2.3.4"}],
        "versions": [{"fingerprint_id": "abc"}],
        "empty_dataset": [],
    }
    results = publish_hour(
        client, datasets, workspace="scan", collection="measurement", tmp_dir=str(tmp_path),
        convert=fake_convert,
    )
    assert set(results.keys()) == {"observations", "versions"}
    assert os.path.exists(tmp_path / "observations.ndjson")  # staged NDJSON still written
    assert os.path.exists(tmp_path / "observations.parquet")  # and converted before upload
    assert client.sessions[0].uploaded[0].endswith(".parquet")
    assert not os.path.exists(tmp_path / "empty_dataset.ndjson")
    assert client.sessions[0].committed_target.workspace == "scan"
    assert client.sessions[0].committed_target.collection == "measurement"


def test_exclusions_commit_with_overwrite_and_everything_else_appends():
    # The scan datasets are append-only logs; `exclusions` is a snapshot of a mutable
    # table where a removal is a real event. Appending snapshots would leave overlapping
    # generations with no way to tell which is current.
    client = FakeClient()
    publish_hour(
        client,
        {"observations": [{"ip": "1.2.3.4"}], "exclusions": [{"ip_or_cidr": "0.0.0.0"}]},
        workspace="scan", collection="measurement", tmp_dir=str(tempfile.mkdtemp()),
        convert=fake_convert,
    )
    resolutions = {}
    for session in client.sessions:
        resolutions.update(session.conflict_resolutions)
    assert resolutions["observations"] == ConflictResolution.APPEND
    assert resolutions["exclusions"] == ConflictResolution.OVERWRITE


def test_exclusion_rows_always_carries_the_sentinel_so_overwrite_always_commits():
    # An emptied exclusions list must still publish. publish_hour skips empty datasets,
    # so without a guaranteed row "all exclusions removed" would commit nothing and
    # leave the previous generation standing - the exact case OVERWRITE exists for.
    assert exclusion_rows([]) == [SENTINEL_EXCLUSION]

    rows = exclusion_rows(
        [
            Exclusion(
                ip_or_cidr="203.0.113.0/24",
                source=ExclusionSource.SELF_SERVE,
                requested_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
                reason="opted out",
                requester_ip="198.51.100.7",
            )
        ]
    )
    assert rows[0] == SENTINEL_EXCLUSION
    assert rows[1]["ip_or_cidr"] == "203.0.113.0/24"
    # .value, not str() - ExclusionSource is a str Enum and str() renders the repr.
    assert rows[1]["source"] == "self-serve"
    assert rows[1]["requested_at"] == "2026-01-02T03:04:05+00:00"


def test_sentinel_exclusion_cannot_change_the_blocklist():
    # It is only there to keep the snapshot non-empty, so it must be inert. 0.0.0.0/8 is
    # already a bogon, and collapse_addresses absorbs the /32 into it.
    without = build_blocklist(exclusion_entries=[])
    with_sentinel = build_blocklist(exclusion_entries=[SENTINEL_EXCLUSION["ip_or_cidr"]])
    assert without == with_sentinel


def test_publish_hour_raises_and_stops_on_inspect_issues(tmp_path):
    client = FakeClient(fail_dataset="observations")
    datasets = {"observations": [{"ip": "1.2.3.4"}], "versions": [{"fingerprint_id": "abc"}]}
    try:
        publish_hour(
            client, datasets, workspace="scan", collection="measurement", tmp_dir=str(tmp_path),
            convert=fake_convert,
        )
        raise AssertionError("expected PublishError")
    except PublishError as exc:
        assert exc.dataset == "observations"


def test_publish_hour_reports_each_commit_before_attempting_the_next(tmp_path):
    """`on_commit` is what lets a caller clear only the datasets that actually landed.
    Without it, a batch that failed partway through left the already-committed datasets
    sitting in pending_dir, and the next cycle's retry committed them a second time -
    duplicate rows for every dataset ordered before the failing one."""
    client = FakeClient(fail_dataset="versions")
    datasets = {"observations": [{"ip": "1.2.3.4"}], "versions": [{"fingerprint_id": "abc"}]}
    committed = []

    try:
        publish_hour(
            client, datasets, workspace="scan", collection="measurement", tmp_dir=str(tmp_path),
            convert=fake_convert, on_commit=lambda name, result: committed.append(name),
        )
        raise AssertionError("expected PublishError")
    except PublishError as exc:
        assert exc.dataset == "versions"

    # observations committed before versions failed - the caller has to be told, since
    # the return value never arrives on this path.
    assert committed == ["observations"]


def test_pending_ndjson_roundtrip(tmp_path):
    pending_dir = str(tmp_path)
    append_ndjson(f"{pending_dir}/observations.ndjson", [{"a": 1}])
    append_ndjson(f"{pending_dir}/observations.ndjson", [{"a": 2}])

    datasets = read_pending_datasets(pending_dir)
    assert datasets == {"observations": [{"a": 1}, {"a": 2}]}

    clear_pending(pending_dir, ["observations"])
    assert read_pending_datasets(pending_dir) == {}


def test_read_pending_datasets_missing_dir_returns_empty():
    assert read_pending_datasets("/nonexistent/path/for/sure") == {}
