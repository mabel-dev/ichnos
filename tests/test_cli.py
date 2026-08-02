from datetime import datetime
from datetime import timezone

import ichnos.cli as cli_module
from ichnos.models import CurrentStateRecord
from ichnos.models import ScheduleEntry
from ichnos.scanner import ScanRunOutcome
from ichnos.models import ScanMetadataRecord
from ichnos.storage.memory import InMemoryStore


def _seeded_store():
    store = InMemoryStore()
    store.schedule.put(ScheduleEntry(protocol="http", port=80, zgrab2_module="http"))
    return store


def test_cmd_scan_pulls_jurisdiction_blocklist_from_s3_when_local_missing(monkeypatch, tmp_path):
    store = _seeded_store()
    monkeypatch.setattr(cli_module, "InMemoryStore", lambda: store)

    downloaded = {}

    def fake_download(bucket, key, path):
        downloaded["args"] = (bucket, key, path)
        with open(path, "w") as f:
            f.write("175.45.176.0/22\n")
        return True

    monkeypatch.setattr(cli_module, "s3_download_file", fake_download)

    fake_outcome = ScanRunOutcome(
        metadata=ScanMetadataRecord(
            scan_id="x", protocol="http", started_at=datetime.now(timezone.utc), status="completed"
        )
    )
    monkeypatch.setattr(cli_module, "run_scan", lambda **kwargs: fake_outcome)

    monkeypatch.setenv("ICHNOS_JURISDICTION_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("ICHNOS_JURISDICTION_S3_KEY", "jurisdiction/blocklist.conf")
    monkeypatch.setenv(
        "ICHNOS_JURISDICTION_BLOCKLIST_PATH", str(tmp_path / "jurisdiction-blocklist.conf")
    )
    monkeypatch.setenv("ICHNOS_BLOCKLIST_PATH", str(tmp_path / "blocklist.conf"))
    monkeypatch.setenv("ICHNOS_PENDING_DIR", str(tmp_path / "pending"))

    args = cli_module.build_parser().parse_args(
        ["scan", "--protocol", "http", "--candidates", "1", "--store", "memory"]
    )
    exit_code = cli_module.cmd_scan(args)

    assert exit_code == 0
    assert downloaded["args"] == ("my-bucket", "jurisdiction/blocklist.conf", str(tmp_path / "jurisdiction-blocklist.conf"))
    with open(tmp_path / "blocklist.conf") as f:
        assert "175.45.176.0/22" in f.read()


def test_cmd_scan_does_not_touch_s3_when_no_bucket_configured(monkeypatch, tmp_path):
    store = _seeded_store()
    monkeypatch.setattr(cli_module, "InMemoryStore", lambda: store)

    def fail_if_called(*a, **k):
        raise AssertionError("s3_download_file should not be called when no bucket is configured")

    monkeypatch.setattr(cli_module, "s3_download_file", fail_if_called)

    fake_outcome = ScanRunOutcome(
        metadata=ScanMetadataRecord(
            scan_id="x", protocol="http", started_at=datetime.now(timezone.utc), status="completed"
        )
    )
    monkeypatch.setattr(cli_module, "run_scan", lambda **kwargs: fake_outcome)

    monkeypatch.delenv("ICHNOS_JURISDICTION_S3_BUCKET", raising=False)
    monkeypatch.setenv(
        "ICHNOS_JURISDICTION_BLOCKLIST_PATH", str(tmp_path / "jurisdiction-blocklist.conf")
    )
    monkeypatch.setenv("ICHNOS_BLOCKLIST_PATH", str(tmp_path / "blocklist.conf"))
    monkeypatch.setenv("ICHNOS_PENDING_DIR", str(tmp_path / "pending"))

    args = cli_module.build_parser().parse_args(
        ["scan", "--protocol", "http", "--candidates", "1", "--store", "memory"]
    )
    assert cli_module.cmd_scan(args) == 0


def test_cmd_jurisdiction_refresh_uploads_to_s3_when_bucket_configured(monkeypatch, tmp_path):
    from ichnos.jurisdiction import JurisdictionRefreshResult

    monkeypatch.setattr(
        cli_module,
        "refresh_jurisdiction_blocklist",
        lambda countries, source: JurisdictionRefreshResult(
            cidrs=["175.45.176.0/22"], source=source, countries=tuple(countries)
        ),
    )

    uploaded = {}

    def fake_upload(bucket, key, path):
        uploaded["args"] = (bucket, key, path)

    monkeypatch.setattr(cli_module, "s3_upload_file", fake_upload)

    monkeypatch.setenv("ICHNOS_JURISDICTION_S3_BUCKET", "my-bucket")
    monkeypatch.setenv("ICHNOS_JURISDICTION_S3_KEY", "jurisdiction/blocklist.conf")
    monkeypatch.setenv(
        "ICHNOS_JURISDICTION_BLOCKLIST_PATH", str(tmp_path / "jurisdiction-blocklist.conf")
    )

    args = cli_module.build_parser().parse_args(["jurisdiction-refresh"])
    assert cli_module.cmd_jurisdiction_refresh(args) == 0
    assert uploaded["args"] == (
        "my-bucket", "jurisdiction/blocklist.conf", str(tmp_path / "jurisdiction-blocklist.conf")
    )


def test_cmd_publish_handles_upload_client_errors_without_losing_pending_data(monkeypatch, tmp_path):
    # Regression test for a real failure mode: publish_hour used to only be guarded
    # against our own PublishError, so anything else opteryx_upload could raise (e.g.
    # AuthorizationError - hit for real against live Opteryx, "authorization denied
    # for action create") crashed cmd_publish with a raw traceback instead of the same
    # clean "log it, hold the files for retry" treatment every other failure gets.
    from opteryx_upload import AuthorizationError

    pending_dir = tmp_path / "pending"
    pending_dir.mkdir()
    (pending_dir / "observations.ndjson").write_text('{"ip": "1.1.1.1"}\n')

    monkeypatch.setenv("ICHNOS_PENDING_DIR", str(pending_dir))
    monkeypatch.setenv("ICHNOS_OPTERYX_CLIENT_ID", "id")
    monkeypatch.setenv("ICHNOS_OPTERYX_CLIENT_SECRET", "secret")

    def fail_publish(*a, **k):
        raise AuthorizationError("authorization denied for action create", status_code=403)

    monkeypatch.setattr(cli_module, "publish_hour", fail_publish)

    args = cli_module.build_parser().parse_args(["publish"])
    assert cli_module.cmd_publish(args) == 1
    assert (pending_dir / "observations.ndjson").exists()  # held for retry, not lost


def test_cmd_jurisdiction_refresh_skips_upload_without_bucket(monkeypatch, tmp_path):
    from ichnos.jurisdiction import JurisdictionRefreshResult

    monkeypatch.setattr(
        cli_module,
        "refresh_jurisdiction_blocklist",
        lambda countries, source: JurisdictionRefreshResult(
            cidrs=["175.45.176.0/22"], source=source, countries=tuple(countries)
        ),
    )

    def fail_if_called(*a, **k):
        raise AssertionError("s3_upload_file should not be called when no bucket is configured")

    monkeypatch.setattr(cli_module, "s3_upload_file", fail_if_called)
    monkeypatch.delenv("ICHNOS_JURISDICTION_S3_BUCKET", raising=False)
    monkeypatch.setenv(
        "ICHNOS_JURISDICTION_BLOCKLIST_PATH", str(tmp_path / "jurisdiction-blocklist.conf")
    )

    args = cli_module.build_parser().parse_args(["jurisdiction-refresh"])
    assert cli_module.cmd_jurisdiction_refresh(args) == 0


def test_cmd_scan_excludes_known_responsive_hosts_from_the_blocklist(monkeypatch, tmp_path):
    # Discovery must not keep re-finding hosts refresh already covers - confirms the
    # wiring end-to-end at the CLI layer, not just that _rebuild_blocklist accepts the
    # parameter.
    store = _seeded_store()
    # 93.184.216.34 (formerly example.com's IP) - deliberately outside every range in
    # blocklist.DEFAULT_BOGONS, so it shows up as its own distinct /32 entry rather
    # than collapsing into an existing bogon CIDR (a real /24 documentation range,
    # 203.0.113.0/24, would have silently absorbed a same-range test IP here).
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="93.184.216.34", port=80, fingerprint_id="abc",
            last_seen_date="2026-08-01",
        )
    )
    monkeypatch.setattr(cli_module, "InMemoryStore", lambda: store)

    fake_outcome = ScanRunOutcome(
        metadata=ScanMetadataRecord(
            scan_id="x", protocol="http", started_at=datetime.now(timezone.utc), status="completed"
        )
    )
    monkeypatch.setattr(cli_module, "run_scan", lambda **kwargs: fake_outcome)

    monkeypatch.delenv("ICHNOS_JURISDICTION_S3_BUCKET", raising=False)
    monkeypatch.setenv(
        "ICHNOS_JURISDICTION_BLOCKLIST_PATH", str(tmp_path / "jurisdiction-blocklist.conf")
    )
    monkeypatch.setenv("ICHNOS_BLOCKLIST_PATH", str(tmp_path / "blocklist.conf"))
    monkeypatch.setenv("ICHNOS_PENDING_DIR", str(tmp_path / "pending"))

    args = cli_module.build_parser().parse_args(
        ["scan", "--protocol", "http", "--candidates", "1", "--store", "memory"]
    )
    assert cli_module.cmd_scan(args) == 0

    with open(tmp_path / "blocklist.conf") as f:
        assert "93.184.216.34/32" in f.read()


def test_cmd_refresh_writes_pending_outcome(monkeypatch, tmp_path):
    store = _seeded_store()
    monkeypatch.setattr(cli_module, "InMemoryStore", lambda: store)

    called_with = {}
    fake_outcome = ScanRunOutcome(
        metadata=ScanMetadataRecord(
            scan_id="x", protocol="http", started_at=datetime.now(timezone.utc), status="completed",
            targets_attempted=1, hosts_responsive=1,
        )
    )

    def fake_run_refresh_scan(**kwargs):
        called_with.update(kwargs)
        return fake_outcome

    monkeypatch.setattr(cli_module, "run_refresh_scan", fake_run_refresh_scan)

    monkeypatch.delenv("ICHNOS_JURISDICTION_S3_BUCKET", raising=False)
    monkeypatch.setenv(
        "ICHNOS_JURISDICTION_BLOCKLIST_PATH", str(tmp_path / "jurisdiction-blocklist.conf")
    )
    monkeypatch.setenv("ICHNOS_BLOCKLIST_PATH", str(tmp_path / "blocklist.conf"))
    monkeypatch.setenv("ICHNOS_PENDING_DIR", str(tmp_path / "pending"))

    args = cli_module.build_parser().parse_args(["refresh", "--protocol", "http", "--store", "memory"])
    assert cli_module.cmd_refresh(args) == 0

    assert called_with["protocol"] == "http"
    assert called_with["port"] == 80
    assert called_with["zgrab2_module"] == "http"
    assert (tmp_path / "pending" / "scan_metadata.ndjson").exists()


def test_cmd_refresh_fails_for_unknown_protocol(monkeypatch, tmp_path):
    store = InMemoryStore()  # no ScheduleEntry seeded
    monkeypatch.setattr(cli_module, "InMemoryStore", lambda: store)
    monkeypatch.setenv("ICHNOS_PENDING_DIR", str(tmp_path / "pending"))

    args = cli_module.build_parser().parse_args(["refresh", "--protocol", "ftp", "--store", "memory"])
    assert cli_module.cmd_refresh(args) == 1
