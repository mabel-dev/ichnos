"""Scan pipeline orchestration (design doc §4).

Follows ZMap's own intended usage model rather than working against it: one
long-running ZMap process per scan window, rate-limited natively via `--rate`, streaming
responsive addresses to stdout as they're found - not hundreds of separate single-target
invocations externally paced by our own rate limiter. That per-candidate approach was
this module's original design and it worked, eventually, but only after chasing down a
run of real production incidents (ARP-resolution hangs, ZMap's campaign-oriented
cooldown dominating per-invocation overhead) that turned out to be inherent to fighting
ZMap's architecture rather than using it - see git history on this file for the full
trail. ZGrab2 remains the fingerprinting tool, invoked per responsive address as ZMap's
stream reports them.

Rate is expressed in whole packets/second (`--rate` doesn't accept fractional values -
confirmed against the real binary, not assumed) - 1 pps is the practical floor. Deployed
at 1pps first, deliberately, to observe real production behaviour before going any
faster; raised to 2pps (see config.py's zmap_rate_pps) once that observation period
showed a low, stable hit rate and no operational issues, then to 4pps after two clean
hours of measured runs at 2pps, and now to 8pps - that last one deployed ahead of its
observation window rather than after it, with the window (7h45m, 93 runs, median 803.3s
against a predicted 803s, no skipped ticks) run immediately afterwards to confirm it,
then 16pps, and now 32pps. See config.py's zmap_rate_pps for the measurements, for why
run duration is a late signal rather than an early one in this series, and for the grab
backlog - which is the thing that actually binds, and which caps this design somewhere
around 50pps regardless of slice size, because grabs below are serial in the reader loop
and their share of a run's window is proportional to the rate. All of these rates are
far looser than this
project's original "one request per 5 seconds" MVP figure, which was our own
conservatism, not a hard requirement.

Running this for real requires the `zmap` and `zgrab2` binaries installed and zmap
running with raw-socket privileges (root, or `cap_net_raw+eip` on the binary) - not
something this module manages, that's a deployment/AMI concern.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from typing import Callable
from typing import List
from typing import Optional
from typing import Tuple

from .blocklist import is_blocked
from .blocklist import read_blocklist_file
from .fingerprint import fingerprint_id
from .models import CurrentStateRecord
from .models import Observation
from .models import ScanMetadataRecord
from .models import VersionRecord
from .logging_setup import get_logger
from .normalize import normalize
from .ratelimit import TokenBucket
from .storage.base import CurrentStateStore
from .storage.base import VersionIndexStore

logger = get_logger(__name__)

CommandRunner = Callable[[List[str], Optional[str]], str]


DEFAULT_COMMAND_TIMEOUT_SECONDS = 30
"""Bound on ZGrab2 invocations (called once per responsive address ZMap's stream
reports - still a discrete subprocess.run call, see grab_one) and on the target_ip
path's single ZMap call. A hung external tool must never be able to stall a scan
indefinitely - discovered the hard way before this existed."""


def _default_run_command(
    cmd: List[str], input: Optional[str] = None, *, timeout: float = DEFAULT_COMMAND_TIMEOUT_SECONDS
) -> str:
    try:
        result = subprocess.run(
            cmd,
            input=input,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.error("command timed out after %gs: %s", timeout, " ".join(cmd))
        return ""

    if result.returncode != 0:
        # A non-zero exit means the tool itself failed to run (bad flag, crash,
        # missing binary) - this must never look identical to "ran fine, found
        # nothing" to a caller that only inspects stdout.
        logger.error(
            "command failed (exit %d): %s -- stderr: %s",
            result.returncode, " ".join(cmd), result.stderr.strip(),
        )
    return result.stdout


DEFAULT_ZMAP_RATE_PPS = 1
"""ZMap's `--rate` only accepts whole packets/second (confirmed: `--rate 0.2` is
rejected outright as an invalid numeric value, not silently rounded) - 1 pps is the
practical floor. Looser than this project's original 5-second-interval MVP figure, but
that was our own conservatism to relax, not a technical or compliance requirement;
1 pps is ZMap's real native minimum, not an approximation."""

DEFAULT_GRAB_CONCURRENCY = 8
"""How many ZGrab2 grabs may be in flight at once during discovery.

Sized against measured load rather than guessed: a grab takes 585ms at the median and
966ms on average (301 hosts, production), and discovery produces well under one hit per
second even at 32pps, so mean demand is around one worker. The headroom is for
timeouts - a 30s grab holds a worker for 30s, and they arrive in clusters - which is
exactly the case that used to stall the reader entirely.

Deliberately a small number. This bounds simultaneous outbound handshakes, and every
one is to a different host, so it does not make the scan heavier for anyone being
scanned - but it is still the knob that decides how much of this machine's network and
file-descriptor budget a run can hold at once, and it should be raised on evidence
rather than in anticipation."""

DEFAULT_ZMAP_COOLDOWN_SECONDS = 3
"""ZMap's own default (8s) is sized for a full campaign - a fixed, one-time tail wait
to catch stragglers, negligible against a normal multi-hour run. Still relevant even in
native streaming mode: it's a single wait at the *end* of the whole scan window now
(not per-target), so a much smaller value is appropriate. Chosen from measurement, not
guesswork: 3 trials each against a known-responsive target found cooldown=1
consistently produced false negatives (unacceptable - this exists to keep "no response"
trustworthy) while cooldown=2 consistently didn't; 3s adds a margin above that."""


def grab_one(
    ip: str,
    port: int,
    module: str,
    blocklist_path: str,
    *,
    run_command: CommandRunner = _default_run_command,
    user_agent: Optional[str] = None,
) -> Optional[dict]:
    """One ZGrab2 handshake against a single target. Returns the parsed `data.<module>`
    object, or None if ZGrab2 produced no parseable result.

    `blocklist_path` is passed through as ZGrab2's own `--blocklist-file` - belt and
    suspenders so ZGrab2 independently enforces the same exclusions ZMap's discovery
    step already did, rather than leaving ZGrab2's separate default blocklist file to
    resolve via `$HOME` (which isn't reliably set across every invocation context this
    runs in - cron, systemd, an ad-hoc shell - and produces a silent, unexplained
    "no result" if ZGrab2 can't find its default file at all, discovered exactly that
    way against a real target).

    `user_agent` identifies the scanner to whoever reads their access log, per AWS's
    network-scanning guidelines (see config.py's `scan_user_agent` for the rationale).
    None means "don't pass the flag", leaving ZGrab2's own default - the identifying
    string lives in config.py rather than being duplicated here, and `cli.py` always
    supplies it on the real path."""
    cmd = ["zgrab2", module, "--port", str(port), "--blocklist-file", blocklist_path]
    if user_agent and module == "http":
        # http-module-only, deliberately: --user-agent is a flag on ZGrab2's http
        # module, not a global one. Passing it to `zgrab2 tls` or `zgrab2 ssh` is an
        # unknown-flag error, so the process exits non-zero having produced nothing -
        # which this function cannot distinguish from a target that simply didn't
        # answer. Getting this wrong would silently turn every HTTPS and SSH grab
        # into a "grab-failed" row rather than failing loudly.
        cmd.extend(["--user-agent", user_agent])
    output = run_command(cmd, f"{ip}\n")
    line = output.strip().splitlines()[0] if output.strip() else ""
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    return record.get("data", {}).get(module)


@dataclass
class ScanRunOutcome:
    metadata: ScanMetadataRecord
    observations: List[Observation] = field(default_factory=list)
    new_versions: List[Tuple[str, VersionRecord]] = field(default_factory=list)
    """(protocol, VersionRecord) pairs - kept per-protocol since a run can, in
    principle, cover more than one dataset."""


def _grab_and_record(
    *,
    scan_id: str,
    protocol: str,
    ip: str,
    port: int,
    zgrab2_module: str,
    blocklist_path: str,
    run_command: CommandRunner,
    current_state: CurrentStateStore,
    version_index: VersionIndexStore,
    today: str,
    clock: Callable[[], datetime],
    outcome: ScanRunOutcome,
    metadata: ScanMetadataRecord,
    user_agent: Optional[str] = None,
    record_lock: Optional["threading.Lock"] = None,
) -> None:
    """Do one ZGrab2 grab against an already-known-responsive `ip` and record the
    result - either a successful fingerprint, or (if ZGrab2 couldn't complete its own
    handshake) a `response_status="grab-failed"` row with no fingerprint.

    `record_lock` serializes everything *after* the grab when this runs on the worker
    pool (_stream_discover_and_grab). The split is deliberate and is where the whole
    benefit comes from: `grab_one` is a subprocess round trip - 585ms at the median,
    966ms mean, up to 30s on timeout, measured over 301 hosts in production - and
    touches no shared state, so it parallelises. Everything after it mutates
    `outcome`/`metadata` and calls the DynamoDB stores, and measures ~12ms in total
    (three round trips at ~3.4ms each), so serializing it costs essentially nothing:
    a single lock passes ~80 hosts/second where the scan produces well under one.

    Serializing also settles the store question rather than betting on it. boto3
    clients are documented thread-safe but resources are not, and both stores are
    resource-backed (storage/dynamodb.py builds Table objects) - holding the lock
    across those calls means the concurrency added here cannot depend on that
    distinction being right.

    None means "no concurrency" - the refresh path and the single-target path call
    this directly, one host at a time, and need no lock.
    """
    lock = record_lock or _NULL_LOCK
    module_result = grab_one(
        ip, port, zgrab2_module, blocklist_path,
        run_command=run_command, user_agent=user_agent,
    )
    with lock:
        _record_grab_result(
            module_result=module_result, scan_id=scan_id, protocol=protocol, ip=ip,
            port=port, zgrab2_module=zgrab2_module, current_state=current_state,
            version_index=version_index, today=today, clock=clock, outcome=outcome,
            metadata=metadata,
        )


class _NullLock:
    """Stand-in for callers that are already single-threaded, so `_grab_and_record`
    has one code path rather than a conditional `with` around the recording block."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc) -> bool:
        return False


_NULL_LOCK = _NullLock()


def _record_grab_result(
    *,
    module_result: Optional[dict],
    scan_id: str,
    protocol: str,
    ip: str,
    port: int,
    zgrab2_module: str,
    current_state: CurrentStateStore,
    version_index: VersionIndexStore,
    today: str,
    clock: Callable[[], datetime],
    outcome: ScanRunOutcome,
    metadata: ScanMetadataRecord,
) -> None:
    """The bookkeeping half of a grab. Split out so the caller can hold a lock across
    exactly this part and not across the subprocess call - see `_grab_and_record`."""
    if module_result is None:
        logger.info("scan %s: %s responded to discovery but zgrab2 produced no result", scan_id, ip)
        outcome.observations.append(
            Observation(
                scan_id=scan_id,
                observed_at=clock(),
                ip=ip,
                port=port,
                protocol=protocol,
                response_status="grab-failed",
                fingerprint_id=None,
            )
        )
        return

    metadata.hosts_responsive += 1
    # normalize() dispatches on the zgrab2 *module* ("http"/"tls"), not the schedule's
    # human-facing protocol label ("http"/"https") - they coincide for HTTP but not
    # HTTPS, which is registered under zgrab2_module="tls" (see ScheduleEntry).
    payload = normalize(zgrab2_module, module_result)
    fp_id = fingerprint_id(payload)

    current = current_state.get(protocol, ip, port)
    is_new_for_host = current is None or current.fingerprint_id != fp_id
    logger.info(
        "scan %s: %s fingerprint=%s (%s)",
        scan_id, ip, fp_id, "new" if is_new_for_host else "unchanged",
    )
    observed_at = clock()
    outcome.observations.append(
        Observation(
            scan_id=scan_id,
            observed_at=observed_at,
            ip=ip,
            port=port,
            protocol=protocol,
            response_status="success",
            fingerprint_id=fp_id,
        )
    )

    if not is_new_for_host:
        return

    current_state.put(
        CurrentStateRecord(
            protocol=protocol,
            ip=ip,
            port=port,
            fingerprint_id=fp_id,
            last_seen_date=today,
        )
    )

    # Two separate questions, deliberately asked separately - conflating them was a real
    # production bug. "Did this host change?" (above) is what CurrentState answers and
    # what the Observation records. "Is this payload one we have never published?" is
    # what the Version datasets need, and only version_index can answer it: the
    # fingerprint hashes the payload alone, so thousands of hosts fronted by the same
    # CDN share one fingerprint, and every one of them used to append its own duplicate
    # copy of the identical row. See VersionIndexStore.claim.
    if not version_index.claim(fp_id):
        logger.info("scan %s: fingerprint=%s already published, no version row", scan_id, fp_id)
        return

    outcome.new_versions.append(
        (
            protocol,
            VersionRecord(
                fingerprint_id=fp_id,
                protocol=protocol,
                first_seen=observed_at,
                payload=payload,
            ),
        )
    )


PopenFactory = Callable[..., "subprocess.Popen"]

DISCOVERY_EXIT_GRACE_SECONDS = 10
"""How long to wait for ZMap to exit on its own once its stdout has closed (EOF),
before concluding it's actually stuck and killing it. Not zero: ZMap's receive thread
still needs to join and it does a little cleanup/logging after the last CSV row is
written - confirmed against the real binary, a real ~1s gap between "recv: thread
finished" and "zmap: completed". 10s is a generous margin above that observed gap."""


def _stream_discover_and_grab(
    *,
    scan_id: str,
    protocol: str,
    port: int,
    zgrab2_module: str,
    seed: int,
    max_targets: int,
    blocklist_path: str,
    current_state: CurrentStateStore,
    version_index: VersionIndexStore,
    today: str,
    clock: Callable[[], datetime],
    outcome: ScanRunOutcome,
    metadata: ScanMetadataRecord,
    gateway_mac: Optional[str],
    cooldown_seconds: int,
    rate_pps: int,
    grab_run_command: CommandRunner,
    popen: PopenFactory,
    user_agent: Optional[str] = None,
    grab_concurrency: int = DEFAULT_GRAB_CONCURRENCY,
) -> None:
    """One ZMap process, run for the whole scan window, streaming classified results as
    they arrive rather than hundreds of separate single-target invocations.

    `--output-filter="repeat = 0"` (dropping ZMap's default `success = 1` requirement)
    is what surfaces RST responses alongside SYN-ACKs - ZMap classifies a reset as a
    definite "host reachable, port closed" rather than genuine silence, and that's real
    signal this project used to discard by relying on ZMap's default filter. Recorded
    directly as `response_status="closed"`, no ZGrab2 grab needed (there's no protocol
    to speak to on a closed port).

    `targets_attempted` is set to `max_targets` directly rather than parsed back out of
    ZMap's own `--metadata-file` - simpler and accurate for the normal case (ZMap
    completes what it was asked to attempt); the command's own 30s-per-grab timeout and
    error logging already surface a genuine early-exit failure separately.

    ZMap's stderr is captured to a temp file (not a pipe - a pipe risks deadlock if
    ZMap ever writes enough to fill the OS pipe buffer while we're only draining
    stdout) and its exit code is checked once it's gone. Real, previously-undetected
    gap: a scan that completed metadata.status="completed" with 1600 attempted, 0
    responsive, in ~20ms instead of the expected ~800s turned out to be ZMap itself
    exiting immediately (plausibly a raw-socket/pcap conflict with another concurrent
    zmap invocation) - completely indistinguishable from "legitimately scanned 1600
    addresses and found nothing" until stderr was actually looked at. `stderr=DEVNULL`
    made that failure mode silent.
    """
    cmd = [
        "zmap",
        "-p", str(port),
        "-n", str(max_targets),
        "--rate", str(rate_pps),
        "--seed", str(seed),
        "--blacklist-file", blocklist_path,
        "--output-fields", "saddr,classification",
        "--output-filter", "repeat = 0",
        "--cooldown-time", str(cooldown_seconds),
    ]
    if gateway_mac:
        cmd.extend(["--gateway-mac", gateway_mac])

    logger.info(
        "scan %s: starting native ZMap discovery, rate=%d pps, max_targets=%d, seed=%d",
        scan_id, rate_pps, max_targets, seed,
    )
    metadata.targets_attempted = max_targets

    # Watchdog, not just the per-grab timeout above: the discovery process itself
    # covers the whole window and must not be able to hang past a generous bound on
    # its own expected runtime (max_targets/rate, plus the cooldown tail, plus margin).
    expected_runtime = max_targets / rate_pps + cooldown_seconds
    watchdog_seconds = expected_runtime * 2 + 30

    stderr_file = tempfile.TemporaryFile(mode="w+")
    proc = popen(cmd, stdout=subprocess.PIPE, stderr=stderr_file, text=True)
    watchdog = threading.Timer(watchdog_seconds, proc.kill)
    watchdog.start()
    record_lock = threading.Lock()

    def _grab_worker(target_ip: str) -> None:
        # Exceptions inside a pool worker land in a Future nobody reads, so an
        # unexpected failure here would silently drop a host and look exactly like a
        # host that never answered. Log it instead - the same reason ZMap's stderr is
        # captured rather than sent to DEVNULL (see this function's docstring).
        try:
            _grab_and_record(
                scan_id=scan_id, protocol=protocol, ip=target_ip, port=port,
                zgrab2_module=zgrab2_module, blocklist_path=blocklist_path,
                run_command=grab_run_command, current_state=current_state,
                version_index=version_index, today=today,
                clock=clock, outcome=outcome, metadata=metadata, user_agent=user_agent,
                record_lock=record_lock,
            )
        except Exception:
            logger.exception("scan %s: grab worker failed for %s", scan_id, target_ip)

    try:
        # Grabs run on a bounded pool rather than inline. ZMap finishes on schedule
        # regardless of what this loop does - it is a separate process, and the stdout
        # pipe buffers - so a serial reader only shows up as the run overrunning once
        # the backlog exceeds the whole window. That bound is set by the rate, not the
        # slice size: grab work scales with candidates while the window is
        # candidates/rate, so the share of a run spent grabbing is proportional to pps
        # (~11% measured at 8pps, ~30% at 16pps). Serial grabbing therefore caps this
        # design near 50pps no matter how the window is sized, which is what this pool
        # exists to lift.
        #
        # It adds no load to any individual target: every concurrent grab is against a
        # different host, and the discovery rate ZMap sends at is untouched. What it
        # changes is how many of *our* outbound handshakes are in flight at once.
        with ThreadPoolExecutor(
            max_workers=grab_concurrency, thread_name_prefix="ichnos-grab"
        ) as pool:
            for line in proc.stdout:
                line = line.strip()
                if not line or "," not in line:
                    continue
                ip, classification = line.split(",", 1)
                ip, classification = ip.strip(), classification.strip()

                if classification == "rst":
                    logger.info("scan %s: %s closed (RST)", scan_id, ip)
                    with record_lock:
                        outcome.observations.append(
                            Observation(
                                scan_id=scan_id,
                                observed_at=clock(),
                                ip=ip,
                                port=port,
                                protocol=protocol,
                                response_status="closed",
                                fingerprint_id=None,
                            )
                        )
                    continue

                if classification != "synack":
                    continue  # unrecognized classification - ignore rather than guess

                logger.info("scan %s: %s responded (synack), grabbing", scan_id, ip)
                pool.submit(_grab_worker, ip)
        # Leaving the `with` waits for every submitted grab, so the run does not report
        # a result until the last one has been recorded. A run whose backlog outlasts
        # ZMap still finishes late rather than losing hosts - the flock guard turns
        # that into a skipped tick, which is the signal to look at, not silent loss.
    finally:
        watchdog.cancel()
        # ZMap closes stdout (ending the loop above via EOF) slightly before it has
        # actually exited - its receive thread still needs to join and it does a
        # little final cleanup/logging after the last CSV row is written (confirmed
        # against the real binary: a real ~1s gap between "recv: thread finished" and
        # "zmap: completed"). Treating "not yet exited" as "hung" and killing
        # immediately was a real bug - it fired on totally normal completions, not
        # just genuine hangs. Give it a grace period to exit on its own first; only
        # kill if it's still not gone after that.
        try:
            proc.wait(timeout=DISCOVERY_EXIT_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            logger.error(
                "scan %s: ZMap discovery still running %gs after its stdout closed, killing",
                scan_id, DISCOVERY_EXIT_GRACE_SECONDS,
            )
            proc.kill()
            proc.wait()

        if proc.returncode != 0:
            stderr_file.seek(0)
            stderr_output = stderr_file.read().strip()
            logger.error(
                "scan %s: ZMap discovery exited with code %d - results are NOT reliable "
                "(targets_attempted/hosts_responsive do not reflect a real scan): %s",
                scan_id, proc.returncode, stderr_output or "(no stderr output)",
            )
            metadata.status = "failed"
        stderr_file.close()


def run_scan(
    *,
    scan_id: str,
    protocol: str,
    port: int,
    zgrab2_module: str,
    seed: int,
    candidate_count: int,
    blocklist_path: str,
    rate_limiter: TokenBucket,
    current_state: CurrentStateStore,
    version_index: VersionIndexStore,
    run_command: CommandRunner = _default_run_command,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    target_ip: Optional[str] = None,
    gateway_mac: Optional[str] = None,
    cooldown_seconds: int = DEFAULT_ZMAP_COOLDOWN_SECONDS,
    rate_pps: int = DEFAULT_ZMAP_RATE_PPS,
    grab_concurrency: int = DEFAULT_GRAB_CONCURRENCY,
    popen: PopenFactory = subprocess.Popen,
    user_agent: Optional[str] = None,
) -> ScanRunOutcome:
    """Run one scan: either a native ZMap discovery pass covering up to
    `candidate_count` targets (ZMap's own `-n`), rate-limited via ZMap's own `--rate`,
    or - if `target_ip` is given - exactly one deliberate attempt against that specific
    address instead, useful for verifying the pipeline against a known-responsive host
    without waiting on ZMap's own random selection to land on something live. That path
    still uses `rate_limiter` (a single ad-hoc call, not the volume this rewrite exists
    for) and still enforces the blocklist explicitly, since it bypasses ZMap's own
    discovery-time exclusion.

    Idempotent per design doc §7: `CurrentState` writes are upserts keyed by
    protocol#ip#port, so re-running the same `(scan_id, seed)` after a crash converges
    to the same end state rather than duplicating history.
    """
    started_at = clock()
    metadata = ScanMetadataRecord(
        scan_id=scan_id, protocol=protocol, started_at=started_at, seed=seed
    )
    outcome = ScanRunOutcome(metadata=metadata)
    today = started_at.date().isoformat()

    if target_ip is not None:
        logger.info(
            "scan %s: targeting %s directly, protocol=%s port=%d (discovery skipped)",
            scan_id, target_ip, protocol, port,
        )
        blocked = is_blocked(target_ip, read_blocklist_file(blocklist_path))
        metadata.targets_attempted += 1
        if blocked:
            logger.warning("scan %s: target %s is blocklisted, refusing to scan", scan_id, target_ip)
        else:
            rate_limiter.wait()
            _grab_and_record(
                scan_id=scan_id, protocol=protocol, ip=target_ip, port=port,
                zgrab2_module=zgrab2_module, blocklist_path=blocklist_path,
                run_command=run_command,
                current_state=current_state, version_index=version_index, today=today, clock=clock,
                outcome=outcome, metadata=metadata, user_agent=user_agent,
            )
        metadata.ended_at = clock()
        metadata.status = "completed"
        return outcome

    _stream_discover_and_grab(
        scan_id=scan_id, protocol=protocol, port=port, zgrab2_module=zgrab2_module,
        seed=seed, max_targets=candidate_count, blocklist_path=blocklist_path,
        current_state=current_state, version_index=version_index,
        today=today, clock=clock, outcome=outcome,
        metadata=metadata, gateway_mac=gateway_mac, cooldown_seconds=cooldown_seconds,
        rate_pps=rate_pps, grab_concurrency=grab_concurrency,
        grab_run_command=run_command, popen=popen,
        user_agent=user_agent,
    )

    metadata.ended_at = clock()
    # _stream_discover_and_grab may already have set "failed" if ZMap itself exited
    # non-zero - don't paper over that by unconditionally stamping "completed".
    if metadata.status != "failed":
        metadata.status = "completed"
    return outcome


def run_refresh_scan(
    *,
    scan_id: str,
    protocol: str,
    port: int,
    zgrab2_module: str,
    blocklist_path: str,
    rate_limiter: TokenBucket,
    current_state: CurrentStateStore,
    version_index: VersionIndexStore,
    run_command: CommandRunner = _default_run_command,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    user_agent: Optional[str] = None,
) -> ScanRunOutcome:
    """Re-test every currently-known-responsive host for `protocol`, to detect drift
    (a server upgrade, a cert rotation, a new fingerprint) since it was last seen.

    No ZMap discovery involved - the whole point is that these addresses are already
    known, there's no needle-in-haystack search left to do. Same shape as
    `run_scan()`'s `target_ip` path (skip discovery, go straight to a ZGrab2 grab),
    just looped over every row `current_state.list_all(protocol)` returns instead of
    one ad-hoc address. Distinct from discovery (design doc's random-sampling `scan`),
    which this project runs on its own separate, more relaxed cadence since it's the
    one actually searching unknown space.
    """
    started_at = clock()
    metadata = ScanMetadataRecord(scan_id=scan_id, protocol=protocol, started_at=started_at)
    outcome = ScanRunOutcome(metadata=metadata)
    today = started_at.date().isoformat()

    known_hosts = current_state.list_all(protocol)
    blocklist_cidrs = read_blocklist_file(blocklist_path)
    logger.info("refresh %s: %d known %s hosts to re-check", scan_id, len(known_hosts), protocol)

    for record in known_hosts:
        metadata.targets_attempted += 1
        # Re-checked per host, not just once up front - a host could have been opted
        # out or jurisdiction-excluded after it was originally recorded (same reason
        # run_scan()'s target_ip path re-checks rather than trusting past inclusion).
        if is_blocked(record.ip, blocklist_cidrs):
            logger.warning("refresh %s: %s is now blocklisted, skipping", scan_id, record.ip)
            continue
        rate_limiter.wait()
        _grab_and_record(
            scan_id=scan_id, protocol=protocol, ip=record.ip, port=port,
            zgrab2_module=zgrab2_module, blocklist_path=blocklist_path,
            run_command=run_command, current_state=current_state,
            version_index=version_index, today=today,
            clock=clock, outcome=outcome, metadata=metadata, user_agent=user_agent,
        )

    metadata.ended_at = clock()
    metadata.status = "completed"
    return outcome
