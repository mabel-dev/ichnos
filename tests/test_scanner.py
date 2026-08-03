import json
import subprocess
from datetime import datetime
from datetime import timezone

import pytest

from ichnos.models import CurrentStateRecord
from ichnos.ratelimit import TokenBucket
from ichnos.scanner import DEFAULT_ZMAP_COOLDOWN_SECONDS
from ichnos.scanner import DEFAULT_ZMAP_RATE_PPS
from ichnos.scanner import _default_run_command
from ichnos.scanner import grab_one
from ichnos.scanner import run_refresh_scan
from ichnos.scanner import run_scan
from ichnos.storage.memory import InMemoryStore


def _fixed_clock():
    moment = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    return lambda: moment


class _FakeProcess:
    """Stands in for subprocess.Popen's return value: an iterable `.stdout` of
    already-decided lines, plus the poll/kill/wait surface run_scan's watchdog and
    exit-grace logic use. `exits_on_its_own=False` simulates a process that's genuinely
    still running once its stdout has EOF'd - `wait()` raises TimeoutExpired (matching
    real subprocess.Popen) until `kill()` is called, same as a real hung process would.
    `exit_code` simulates ZMap itself exiting non-zero (e.g. a real raw-socket
    conflict) - `.returncode` only becomes accurate once wait()/poll() has resolved
    the process, matching real subprocess.Popen semantics."""

    def __init__(self, lines, exits_on_its_own=True, exit_code=0):
        self.stdout = iter(lines)
        self.killed = False
        self.returncode = None
        self._exits_on_its_own = exits_on_its_own
        self._exit_code = exit_code

    def poll(self):
        if self._exits_on_its_own or self.killed:
            self.returncode = self._exit_code
            return self.returncode
        return None

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        if self._exits_on_its_own or self.killed:
            self.returncode = self._exit_code
            return self.returncode
        raise subprocess.TimeoutExpired(cmd="zmap", timeout=timeout)


def _fake_popen(lines, calls, **kwargs):
    def popen(cmd, **_):
        calls.append(cmd)
        return _FakeProcess(lines, **kwargs)

    return popen


def test_run_scan_builds_the_real_zmap_flags_not_blocklist():
    # Regression test for a real, previously-undetected bug in the old per-candidate
    # design: no test verified the exact flag name ZMap was invoked with, only that
    # "zmap" was called at all - so a wrong flag name (--blocklist-file, which doesn't
    # exist on this installed ZMap - the real flag is --blacklist-file) went undetected
    # through every test run and the entire deployment until manually run by hand
    # against the real binary.
    calls = []
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="flag-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=5, blocklist_path="/tmp/blocklist.conf", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls),
    )

    cmd = calls[0]
    assert "--blacklist-file" in cmd
    assert "--blocklist-file" not in cmd


def test_run_scan_uses_the_native_rate_flag_as_an_integer():
    # ZMap's --rate only accepts whole packets/second - confirmed against the real
    # binary, not assumed. This is the whole point of the native rewrite: throttling is
    # ZMap's own job now, not an external per-candidate delay.
    calls = []
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="rate-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=5, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls),
    )

    cmd = calls[0]
    assert cmd[cmd.index("--rate") + 1] == str(DEFAULT_ZMAP_RATE_PPS)

    calls.clear()
    run_scan(
        scan_id="rate-test-2", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=5, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls), rate_pps=7,
    )
    assert calls[0][calls[0].index("--rate") + 1] == "7"


def test_run_scan_passes_max_targets_seed_and_cooldown():
    calls = []
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="params-test", protocol="http", port=80, zgrab2_module="http", seed=99,
        candidate_count=40, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls),
    )

    cmd = calls[0]
    assert cmd[cmd.index("-n") + 1] == "40"
    assert cmd[cmd.index("--seed") + 1] == "99"
    assert cmd[cmd.index("--cooldown-time") + 1] == str(DEFAULT_ZMAP_COOLDOWN_SECONDS)


def test_run_scan_overrides_the_output_filter_to_include_rst():
    # ZMap's own default filter ("success = 1 && repeat = 0") silently discards RST
    # responses - a definite "host reachable, port closed" signal this rewrite exists
    # to surface (as response_status="closed") rather than continue collapsing into
    # indistinguishable silence.
    calls = []
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="filter-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=5, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls),
    )

    cmd = calls[0]
    assert cmd[cmd.index("--output-filter") + 1] == "repeat = 0"


def test_run_scan_passes_gateway_mac_when_given():
    calls = []
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="gw-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=2, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls), gateway_mac="11:22:33:44:55:66",
    )

    cmd = calls[0]
    assert "--gateway-mac" in cmd
    assert cmd[cmd.index("--gateway-mac") + 1] == "11:22:33:44:55:66"


def test_run_scan_omits_gateway_mac_when_not_given():
    calls = []
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="no-gw-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=2, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], calls),
    )

    assert "--gateway-mac" not in calls[0]


def test_grab_one_uses_the_zgrab2_blocklist_flag():
    # ZGrab2's actual flag is --blocklist-file (newer terminology) - the opposite of
    # ZMap's --blacklist-file above. Both are correct for their respective tools;
    # this pins the deliberate difference so it can't silently drift either way.
    calls = []

    def run_command(cmd, input=None):
        calls.append(cmd)
        return ""

    grab_one("1.2.3.4", 80, "http", "/tmp/blocklist.conf", run_command=run_command)

    assert "--blocklist-file" in calls[0]
    assert "--blacklist-file" not in calls[0]


def test_grab_one_sends_the_identifying_user_agent_for_http():
    # AWS's network-scanning guidelines ask HTTP scanners to carry "meaningful content
    # in user agent strings" so an operator reading their access log can identify the
    # scanner and find the opt-out. ZGrab2's own default is generic, so this has to be
    # passed explicitly - if it stops being passed, the probe becomes anonymous again.
    calls = []

    def run_command(cmd, input=None):
        calls.append(cmd)
        return ""

    grab_one(
        "1.2.3.4", 80, "http", "/tmp/blocklist.conf",
        run_command=run_command, user_agent="ichnos/1.0 (+https://ichnos.online/x)",
    )

    assert "--user-agent" in calls[0]
    assert calls[0][calls[0].index("--user-agent") + 1] == "ichnos/1.0 (+https://ichnos.online/x)"


@pytest.mark.parametrize("module", ["tls", "ssh"])
def test_grab_one_omits_user_agent_for_non_http_modules(module):
    # --user-agent is a flag on ZGrab2's *http* module, not a global one. Passing it to
    # `zgrab2 tls` or `zgrab2 ssh` is an unknown-flag error: the process exits non-zero
    # having produced no output, which grab_one cannot distinguish from a target that
    # simply didn't answer. That would silently turn every HTTPS and SSH grab into a
    # "grab-failed" row - a total loss of two protocols, with nothing in the logs
    # pointing at the cause. This is the guard against that.
    calls = []

    def run_command(cmd, input=None):
        calls.append(cmd)
        return ""

    grab_one(
        "1.2.3.4", 443, module, "/tmp/blocklist.conf",
        run_command=run_command, user_agent="ichnos/1.0",
    )

    assert "--user-agent" not in calls[0]


def test_run_scan_threads_the_user_agent_down_to_the_grab():
    # The flag is only useful if it survives the whole call chain to the actual ZGrab2
    # invocation - the parameter existing on run_scan() proves nothing on its own.
    calls = []

    def run_command(cmd, input=None):
        calls.append(cmd)
        return json.dumps({"data": {"http": {"result": {"response": {"status_code": 200}}}}})

    run_scan(
        scan_id="s1",
        protocol="http",
        port=80,
        zgrab2_module="http",
        seed=1,
        candidate_count=1,
        blocklist_path="/tmp/blocklist.conf",
        rate_limiter=TokenBucket(0.001, burst=1),
        current_state=InMemoryStore().current_state,
        run_command=run_command,
        target_ip="1.2.3.4",
        user_agent="ichnos/1.0 (+https://ichnos.online/responsible-scanning)",
    )

    zgrab_calls = [c for c in calls if c[0] == "zgrab2"]
    assert zgrab_calls, "expected a zgrab2 invocation"
    assert "--user-agent" in zgrab_calls[0]


def test_run_refresh_scan_threads_the_user_agent_down_to_the_grab():
    # Same guarantee for the refresh path - it's a separate call chain, and it's the
    # one that revisits the *same* hosts daily, so an unidentified probe there is the
    # one an operator is most likely to notice repeatedly.
    store = InMemoryStore()
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="1.2.3.4", port=80,
            fingerprint_id="old", last_seen_date="2025-01-01",
        )
    )
    calls = []

    def run_command(cmd, input=None):
        calls.append(cmd)
        return json.dumps({"data": {"http": {"result": {"response": {"status_code": 200}}}}})

    run_refresh_scan(
        scan_id="r1",
        protocol="http",
        port=80,
        zgrab2_module="http",
        blocklist_path="/tmp/blocklist.conf",
        rate_limiter=TokenBucket(0.001, burst=1),
        current_state=store.current_state,
        run_command=run_command,
        user_agent="ichnos/1.0 (+https://ichnos.online/responsible-scanning)",
    )

    zgrab_calls = [c for c in calls if c[0] == "zgrab2"]
    assert zgrab_calls, "expected a zgrab2 invocation"
    assert "--user-agent" in zgrab_calls[0]


def test_default_run_command_logs_error_on_nonzero_exit(caplog):
    import logging

    with caplog.at_level(logging.ERROR, logger="ichnos.scanner"):
        output = _default_run_command(["ls", "--this-flag-does-not-exist"])

    assert output == ""  # still returns (empty) stdout rather than raising
    assert any("command failed" in record.message for record in caplog.records)


def test_default_run_command_silent_on_success():
    output = _default_run_command(["echo", "hello"])
    assert output.strip() == "hello"


def test_default_run_command_times_out_rather_than_hanging_forever(caplog):
    # Regression test for a real production incident: a specific target reliably
    # caused a plain `zmap -n 1` invocation to hang indefinitely, blocking two
    # concurrently-running cron-triggered scans until manually killed. A hung command
    # must degrade to a recorded failure within a bounded time, never block forever.
    import logging

    with caplog.at_level(logging.ERROR, logger="ichnos.scanner"):
        output = _default_run_command(["sleep", "5"], timeout=0.2)

    assert output == ""
    assert any("timed out" in record.message for record in caplog.records)


def test_run_scan_records_observation_and_new_version_for_responsive_host():
    zgrab_result = {
        "data": {"http": {"result": {"response": {"status_code": 200, "headers": {"Server": ["nginx"]}}}}}
    }

    def run_command(cmd, input=None):
        assert cmd[0] == "zgrab2"
        return json.dumps(zgrab_result) + "\n"

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="http-test",
        protocol="http",
        port=80,
        zgrab2_module="http",
        seed=42,
        candidate_count=3,
        blocklist_path="/tmp/ichnos-test-blocklist.conf",
        rate_limiter=limiter,
        current_state=store.current_state,
        run_command=run_command,
        clock=_fixed_clock(),
        popen=_fake_popen(["203.0.113.5,synack"], []),
    )

    assert outcome.metadata.targets_attempted == 3  # -n, the discovery budget requested
    assert outcome.metadata.hosts_responsive == 1
    assert outcome.metadata.status == "completed"
    assert len(outcome.observations) == 1
    assert outcome.observations[0].ip == "203.0.113.5"
    assert outcome.observations[0].response_status == "success"
    assert outcome.observations[0].fingerprint_id
    assert len(outcome.new_versions) == 1
    assert outcome.new_versions[0][0] == "http"


def test_run_scan_records_closed_for_rst_without_grabbing():
    # RST is real signal ZMap's default filter would otherwise silently discard: the
    # host is reachable, the port is just refused. No ZGrab2 call should happen for it.
    def run_command(cmd, input=None):
        raise AssertionError("a closed port should never reach zgrab2")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="rst-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=1, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        popen=_fake_popen(["203.0.113.9,rst"], []),
    )

    assert len(outcome.observations) == 1
    assert outcome.observations[0].ip == "203.0.113.9"
    assert outcome.observations[0].response_status == "closed"
    assert outcome.observations[0].fingerprint_id is None
    assert outcome.metadata.hosts_responsive == 0  # only completed grabs count
    assert outcome.new_versions == []


def test_run_scan_dedupes_unchanged_fingerprint_on_rerun():
    zgrab_result = {
        "data": {"http": {"result": {"response": {"status_code": 200, "headers": {}}}}}
    }

    def run_command(cmd, input=None):
        return json.dumps(zgrab_result) + "\n"

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    first = run_scan(
        scan_id="run-1", protocol="http", port=80, zgrab2_module="http", seed=42,
        candidate_count=3, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        popen=_fake_popen(["203.0.113.5,synack"], []),
    )
    second = run_scan(
        scan_id="run-2", protocol="http", port=80, zgrab2_module="http", seed=42,
        candidate_count=3, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        popen=_fake_popen(["203.0.113.5,synack"], []),
    )

    assert len(first.new_versions) == 1
    assert len(second.observations) == 1  # still observed
    assert len(second.new_versions) == 0  # but unchanged, so no new Version row


def test_run_scan_no_responsive_hosts():
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="empty-run", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=5, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(),
        popen=_fake_popen([], []),  # zmap streams nothing - no responses at all
    )

    assert outcome.metadata.targets_attempted == 5
    assert outcome.metadata.hosts_responsive == 0
    assert outcome.observations == []
    assert outcome.new_versions == []


def test_run_scan_records_grab_failed_when_zgrab2_produces_nothing():
    # ZMap finds a live host, but ZGrab2's own handshake fails/times out - this should
    # still produce an Observation (response_status="grab-failed", no fingerprint),
    # not be silently dropped the way a ZMap-level non-response is.
    def run_command(cmd, input=None):
        assert cmd[0] == "zgrab2"
        return ""  # no result at all

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="grab-fail-test", protocol="http", port=80, zgrab2_module="http", seed=42,
        candidate_count=1, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        popen=_fake_popen(["203.0.113.5,synack"], []),
    )

    assert outcome.metadata.targets_attempted == 1
    assert outcome.metadata.hosts_responsive == 0  # only counts a completed grab
    assert len(outcome.observations) == 1
    assert outcome.observations[0].response_status == "grab-failed"
    assert outcome.observations[0].fingerprint_id is None
    assert outcome.new_versions == []


def test_run_scan_ignores_unrecognized_classifications():
    def run_command(cmd, input=None):
        raise AssertionError("should never reach zgrab2 for a non-synack line")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="weird-line-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=1, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        popen=_fake_popen(["not,a,valid,line", "", "203.0.113.5,unknown-classification"], []),
    )

    assert outcome.observations == []


def test_run_scan_kills_the_zmap_process_if_still_running_after_its_exit_grace_period():
    # Real production incident, not speculative: a hung ZMap invocation blocked two
    # concurrently-running cron-triggered scans until manually killed. The whole-window
    # native process needs the same guarantee the old per-candidate design eventually
    # got: it must never be able to block a scan indefinitely.
    procs = []

    def popen(cmd, **_):
        proc = _FakeProcess([], exits_on_its_own=False)
        procs.append(proc)
        return proc

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="hang-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=2, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(), popen=popen,
    )

    # the fake process's wait() keeps raising TimeoutExpired (still running) even
    # after its stdout stream ended - run_scan must notice, past the exit grace
    # period, and kill it rather than trust it will exit cleanly on its own.
    assert procs[0].killed


def test_run_scan_does_not_kill_a_process_that_exits_promptly_after_streaming():
    # Regression test for a real bug: ZMap closes its stdout (ending the streaming
    # loop) slightly before it has actually exited - it still has to join its receive
    # thread and do a little cleanup, confirmed against the real binary. The original
    # implementation treated "not yet exited immediately after EOF" as "hung" and
    # killed it on every single normal completion, not just genuine hangs.
    procs = []

    def popen(cmd, **_):
        proc = _FakeProcess([], exits_on_its_own=True)
        procs.append(proc)
        return proc

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    run_scan(
        scan_id="normal-exit-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=2, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(), popen=popen,
    )

    assert not procs[0].killed


def test_run_scan_marks_status_failed_when_zmap_exits_non_zero(caplog):
    # Real production incident, not speculative: a scan reported "1600 attempted, 0
    # responsive, completed" in ~20ms - not the ~800s a real run takes. ZMap itself had
    # exited immediately (plausibly a raw-socket/pcap conflict with another concurrent
    # zmap invocation), and the code had no way to tell that apart from "legitimately
    # scanned 1600 addresses and found nothing" - stderr was discarded and the exit
    # code was never checked. That silently produced fabricated-looking "zero
    # responsive" data indistinguishable from a real null result.
    import logging

    def popen(cmd, **_):
        return _FakeProcess([], exits_on_its_own=True, exit_code=1)

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    with caplog.at_level(logging.ERROR, logger="ichnos.scanner"):
        outcome = run_scan(
            scan_id="zmap-fail-test", protocol="http", port=80, zgrab2_module="http", seed=1,
            candidate_count=1600, blocklist_path="/tmp/x", rate_limiter=limiter,
            current_state=store.current_state, clock=_fixed_clock(), popen=popen,
        )

    assert outcome.metadata.status == "failed"
    assert any("exited with code 1" in r.message for r in caplog.records)


def test_run_scan_status_stays_completed_when_zmap_exits_zero():
    def popen(cmd, **_):
        return _FakeProcess([], exits_on_its_own=True, exit_code=0)

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="zmap-ok-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=2, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, clock=_fixed_clock(), popen=popen,
    )

    assert outcome.metadata.status == "completed"


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

    def popen(cmd, **kwargs):
        raise AssertionError("target_ip mode should never invoke zmap discovery")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="target-test", protocol="http", port=80, zgrab2_module="http", seed=1,
        candidate_count=99,  # irrelevant in target_ip mode
        blocklist_path="/tmp/nonexistent-blocklist.conf", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        target_ip="1.1.1.1", popen=popen,
    )

    assert outcome.metadata.targets_attempted == 1
    assert outcome.metadata.hosts_responsive == 1
    assert len(outcome.observations) == 1
    assert outcome.observations[0].ip == "1.1.1.1"
    assert outcome.observations[0].response_status == "success"
    assert len(outcome.new_versions) == 1


def test_run_scan_normalizes_by_zgrab2_module_not_protocol_label():
    # protocol="https" is the schedule's human-facing label (and the dataset name
    # results get published under) - the zgrab2 *module* for HTTPS is "tls", and
    # normalize() must dispatch on that, not on `protocol`. Regression test for a real
    # bug: this coincided for HTTP (module also "http") so nothing caught it until the
    # first live HTTPS grab actually succeeded against a real target.
    zgrab_result = {
        "data": {
            "tls": {
                "result": {
                    "handshake_log": {
                        "server_hello": {"version": {"name": "TLSv1.3"}},
                    }
                }
            }
        }
    }

    def run_command(cmd, input=None):
        if cmd[0] == "zgrab2":
            assert cmd[1] == "tls"
            return json.dumps(zgrab_result) + "\n"
        raise AssertionError(f"unexpected command: {cmd}")

    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_scan(
        scan_id="https-test", protocol="https", port=443, zgrab2_module="tls", seed=1,
        candidate_count=1, blocklist_path="/tmp/x", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
        target_ip="1.1.1.1",
    )

    assert outcome.metadata.hosts_responsive == 1
    assert len(outcome.observations) == 1
    assert outcome.observations[0].response_status == "success"
    assert len(outcome.new_versions) == 1
    assert outcome.new_versions[0][0] == "https"  # dataset name still the protocol label
    assert outcome.new_versions[0][1].payload["version"] == "TLSv1.3"


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


def test_run_refresh_scan_regrabs_every_known_host():
    zgrab_result = {
        "data": {"http": {"result": {"response": {"status_code": 200, "headers": {}}}}}
    }
    calls = []

    def run_command(cmd, input=None):
        calls.append(input.strip())
        return json.dumps(zgrab_result) + "\n"

    store = InMemoryStore()
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="203.0.113.5", port=80, fingerprint_id="old",
            last_seen_date="2026-07-01",
        )
    )
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="203.0.113.9", port=80, fingerprint_id="old2",
            last_seen_date="2026-07-01",
        )
    )
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_refresh_scan(
        scan_id="refresh-test", protocol="http", port=80, zgrab2_module="http",
        blocklist_path="/tmp/nonexistent-blocklist.conf", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )

    assert outcome.metadata.targets_attempted == 2
    assert sorted(calls) == ["203.0.113.5", "203.0.113.9"]
    assert len(outcome.observations) == 2
    assert all(o.response_status == "success" for o in outcome.observations)
    # fingerprint differs from the stale "old"/"old2" values already on record, so both
    # count as a new version - this is exactly the drift-detection refresh exists for.
    assert len(outcome.new_versions) == 2


def test_run_refresh_scan_skips_a_host_that_is_now_blocklisted(tmp_path):
    blocklist_path = str(tmp_path / "blocklist.conf")
    with open(blocklist_path, "w") as f:
        f.write("203.0.113.9/32\n")

    def run_command(cmd, input=None):
        if input and input.strip() == "203.0.113.9":
            raise AssertionError("a blocklisted host should never reach zgrab2")
        return json.dumps(
            {"data": {"http": {"result": {"response": {"status_code": 200, "headers": {}}}}}}
        ) + "\n"

    store = InMemoryStore()
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="203.0.113.5", port=80, fingerprint_id="old",
            last_seen_date="2026-07-01",
        )
    )
    store.current_state.put(
        CurrentStateRecord(
            protocol="http", ip="203.0.113.9", port=80, fingerprint_id="old2",
            last_seen_date="2026-07-01",
        )
    )
    limiter = TokenBucket(0.001, burst=1)

    outcome = run_refresh_scan(
        scan_id="refresh-blocked-test", protocol="http", port=80, zgrab2_module="http",
        blocklist_path=blocklist_path, rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )

    # both are still counted as attempted - the blocklisted one is just skipped, not
    # silently dropped from the count.
    assert outcome.metadata.targets_attempted == 2
    assert len(outcome.observations) == 1
    assert outcome.observations[0].ip == "203.0.113.5"


def test_run_refresh_scan_no_known_hosts():
    store = InMemoryStore()
    limiter = TokenBucket(0.001, burst=1)

    def run_command(cmd, input=None):
        raise AssertionError("nothing to grab when there are no known hosts")

    outcome = run_refresh_scan(
        scan_id="refresh-empty-test", protocol="http", port=80, zgrab2_module="http",
        blocklist_path="/tmp/nonexistent-blocklist.conf", rate_limiter=limiter,
        current_state=store.current_state, run_command=run_command, clock=_fixed_clock(),
    )

    assert outcome.metadata.targets_attempted == 0
    assert outcome.observations == []
    assert outcome.metadata.status == "completed"
