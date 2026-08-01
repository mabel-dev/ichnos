import json
from datetime import datetime
from datetime import timezone

from ichnos.ratelimit import TokenBucket
from ichnos.scanner import derive_seed
from ichnos.scanner import run_scan
from ichnos.storage.memory import InMemoryStore


def _fixed_clock():
    moment = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    return lambda: moment


def _fake_run_command(responsive_seed, zgrab_result):
    def run_command(cmd, input=None):
        if cmd[0] == "zmap":
            seed = cmd[cmd.index("--seed") + 1]
            return "203.0.113.5\n" if seed == responsive_seed else ""
        if cmd[0] == "zgrab2":
            return json.dumps(zgrab_result) + "\n"
        raise AssertionError(f"unexpected command: {cmd}")

    return run_command


def test_run_scan_records_observation_and_new_version_for_responsive_host():
    base_seed = 42
    responsive_seed = str(derive_seed(base_seed, 0))
    zgrab_result = {
        "data": {"http": {"result": {"response": {"status_code": 200, "headers": {"Server": ["nginx"]}}}}}
    }

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="http-test",
        protocol="http",
        port=80,
        zgrab2_module="http",
        seed=base_seed,
        candidate_count=3,
        blocklist_path="/tmp/ichnos-test-blocklist.conf",
        rate_limiter=limiter,
        current_state=store.current_state,
        run_command=_fake_run_command(responsive_seed, zgrab_result),
        clock=_fixed_clock(),
    )

    assert outcome.metadata.targets_attempted == 3
    assert outcome.metadata.hosts_responsive == 1
    assert outcome.metadata.status == "completed"
    assert len(outcome.observations) == 1
    assert outcome.observations[0].ip == "203.0.113.5"
    assert outcome.observations[0].fingerprint_id
    assert len(outcome.new_versions) == 1
    assert outcome.new_versions[0][0] == "http"


def test_run_scan_dedupes_unchanged_fingerprint_on_rerun():
    base_seed = 42
    responsive_seed = str(derive_seed(base_seed, 0))
    zgrab_result = {
        "data": {"http": {"result": {"response": {"status_code": 200, "headers": {}}}}}
    }
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)
    run_command = _fake_run_command(responsive_seed, zgrab_result)

    first = run_scan(
        scan_id="run-1", protocol="http", port=80, zgrab2_module="http", seed=base_seed,
        candidate_count=3, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )
    second = run_scan(
        scan_id="run-2", protocol="http", port=80, zgrab2_module="http", seed=base_seed,
        candidate_count=3, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )

    assert len(first.new_versions) == 1
    assert len(second.observations) == 1  # still observed
    assert len(second.new_versions) == 0  # but unchanged, so no new Version row


def test_run_scan_no_responsive_hosts():
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)
    run_command = lambda cmd, input=None: ""  # zmap never finds anything

    outcome = run_scan(
        scan_id="empty-run", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=5, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )

    assert outcome.metadata.targets_attempted == 5
    assert outcome.metadata.hosts_responsive == 0
    assert outcome.observations == []
    assert outcome.new_versions == []


def test_run_scan_records_grab_failed_when_zgrab2_produces_nothing():
    # ZMap finds a live host, but ZGrab2's own handshake fails/times out - this should
    # still produce an Observation (response_status="grab-failed", no fingerprint),
    # not be silently dropped the way a ZMap-level non-response is.
    base_seed = 42
    responsive_seed = str(derive_seed(base_seed, 0))

    def run_command(cmd, input=None):
        if cmd[0] == "zmap":
            seed = cmd[cmd.index("--seed") + 1]
            return "203.0.113.5\n" if seed == responsive_seed else ""
        if cmd[0] == "zgrab2":
            return ""  # no result at all
        raise AssertionError(f"unexpected command: {cmd}")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="grab-fail-test", protocol="http", port=80, zgrab2_module="http", seed=base_seed,
        candidate_count=1, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )

    assert outcome.metadata.targets_attempted == 1
    assert outcome.metadata.hosts_responsive == 0  # only counts a completed grab
    assert len(outcome.observations) == 1
    assert outcome.observations[0].response_status == "grab-failed"
    assert outcome.observations[0].fingerprint_id is None
    assert outcome.new_versions == []


def test_run_scan_target_ip_skips_discovery_and_grabs_directly():
    zgrab_result = {
        "data": {"http": {"result": {"response": {"status_code": 200, "headers": {}}}}}
    }

    def run_command(cmd, input=None):
        if cmd[0] == "zmap":
            raise AssertionError("target_ip mode should never invoke zmap discovery")
        if cmd[0] == "zgrab2":
            assert input == "1.1.1.1\n"
            return json.dumps(zgrab_result) + "\n"
        raise AssertionError(f"unexpected command: {cmd}")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="target-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=99,  # irrelevant in target_ip mode
        blocklist_path="/tmp/nonexistent-blocklist.conf", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        target_ip="1.1.1.1",
    )

    assert outcome.metadata.targets_attempted == 1
    assert outcome.metadata.hosts_responsive == 1
    assert len(outcome.observations) == 1
    assert outcome.observations[0].ip == "1.1.1.1"
    assert outcome.observations[0].response_status == "success"
    assert len(outcome.new_versions) == 1


def test_run_scan_target_ip_refuses_a_blocklisted_target(tmp_path):
    blocklist_path = str(tmp_path / "blocklist.conf")
    with open(blocklist_path, "w") as f:
        f.write("175.45.176.0/22\n")

    def run_command(cmd, input=None):
        raise AssertionError("a blocklisted target should never reach zmap or zgrab2")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="target-blocked-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=1, blocklist_path=blocklist_path, rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        target_ip="175.45.176.5",
    )

    assert outcome.metadata.targets_attempted == 1
    assert outcome.metadata.hosts_responsive == 0
    assert outcome.observations == []
    assert outcome.metadata.status == "completed"
