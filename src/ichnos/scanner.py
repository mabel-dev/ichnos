"""Scan pipeline orchestration (design doc §4).

At the MVP throttle (no more than one request per 5 seconds, design decision - see
ratelimit.py), ZMap's normal high-throughput discovery/ztee-buffering machinery isn't
needed: a small number of single-target probes, paced by the rate limiter and run
sequentially, is simpler and equally correct at this volume. ZMap is still the
discovery tool and ZGrab2 still the fingerprinting tool, per the spec's technology
requirement - this just calls them one target at a time instead of as a bulk sweep.

Rate-budget accounting is deliberately conservative: *both* the ZMap discovery probe
and (if the host is up) the follow-on ZGrab2 handshake each consume one token from the
same global budget, so a single responsive host can cost two ticks of the throttle, not
one. This is the stricter of the two plausible readings of "no more than one request
per 5 seconds" and is called out explicitly (see design doc's open questions) as an
assumption, not a certainty.

Running this for real requires the `zmap` and `zgrab2` binaries installed and zmap
running with raw-socket privileges (root, or `cap_net_raw+eip` on the binary) - not
something this module manages, that's a deployment/AMI concern.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from dataclasses import field
from datetime import date
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

logger = get_logger(__name__)

CommandRunner = Callable[[List[str], Optional[str]], str]


def _default_run_command(cmd: List[str], input: Optional[str] = None) -> str:
    result = subprocess.run(
        cmd,
        input=input,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def derive_seed(base_seed: int, index: int) -> int:
    """A distinct pseudorandom seed per single-target probe within a run, so
    consecutive probes sample different positions in ZMap's address permutation
    rather than repeating the same target. Not cryptographic - just decorrelation."""
    return (base_seed * 1_000_003 + index + 1) & 0xFFFFFFFF


def probe_one(
    port: int,
    seed: int,
    blocklist_path: str,
    *,
    run_command: CommandRunner = _default_run_command,
) -> Optional[str]:
    """One ZMap discovery probe against a single pseudorandom target. Returns the
    responsive IP, or None if it didn't answer (or was blocklisted/excluded)."""
    output = run_command(
        [
            "zmap",
            "-p",
            str(port),
            "-n",
            "1",
            "--seed",
            str(seed),
            "--blocklist-file",
            blocklist_path,
        ],
        None,
    )
    line = output.strip().splitlines()[0].strip() if output.strip() else ""
    return line or None


def grab_one(
    ip: str,
    port: int,
    module: str,
    blocklist_path: str,
    *,
    run_command: CommandRunner = _default_run_command,
) -> Optional[dict]:
    """One ZGrab2 handshake against a single target. Returns the parsed `data.<module>`
    object, or None if ZGrab2 produced no parseable result.

    `blocklist_path` is passed through as ZGrab2's own `--blocklist-file` - belt and
    suspenders so ZGrab2 independently enforces the same exclusions ZMap's discovery
    step already did, rather than leaving ZGrab2's separate default blocklist file to
    resolve via `$HOME` (which isn't reliably set across every invocation context this
    runs in - cron, systemd, an ad-hoc shell - and produces a silent, unexplained
    "no result" if ZGrab2 can't find its default file at all, discovered exactly that
    way against a real target)."""
    output = run_command(
        ["zgrab2", module, "--port", str(port), "--blocklist-file", blocklist_path],
        f"{ip}\n",
    )
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
    today: str,
    clock: Callable[[], datetime],
    outcome: ScanRunOutcome,
    metadata: ScanMetadataRecord,
) -> None:
    """Shared by both the random-candidate loop and the single-target path below: do
    one ZGrab2 grab against an already-known-responsive `ip` and record the result.

    Always records *something* for a host that answered ZMap's discovery probe -
    either a successful fingerprint, or (if ZGrab2 couldn't complete its own handshake)
    a `response_status="grab-failed"` row with no fingerprint. The one case that can't
    be recorded per-host is a target ZMap's discovery probe never got an answer from at
    all: there's no protocol response to attach a record to, and no query mode where
    ZMap tells us what a specific unanswered address even was - that absence is only
    visible in aggregate, via `targets_attempted` vs `hosts_responsive` on the
    ScanMetadata row (which is queued for publish every run regardless).
    """
    module_result = grab_one(ip, port, zgrab2_module, blocklist_path, run_command=run_command)
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
    payload = normalize(protocol, module_result)
    fp_id = fingerprint_id(payload)

    current = current_state.get(protocol, ip, port)
    is_new = current is None or current.fingerprint_id != fp_id
    logger.info(
        "scan %s: %s fingerprint=%s (%s)", scan_id, ip, fp_id, "new" if is_new else "unchanged",
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

    if is_new:
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
        current_state.put(
            CurrentStateRecord(
                protocol=protocol,
                ip=ip,
                port=port,
                fingerprint_id=fp_id,
                last_seen_date=today,
            )
        )


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
    run_command: CommandRunner = _default_run_command,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    target_ip: Optional[str] = None,
) -> ScanRunOutcome:
    """Run one scan: up to `candidate_count` single-target probes, throttled by
    `rate_limiter`, fingerprinting and dedupe-checking every responsive host.

    `target_ip`, when given, bypasses random candidate selection entirely and makes
    exactly one attempt against that specific address instead - useful for verifying
    the pipeline end-to-end against a known-responsive host (e.g. a public DNS
    resolver) without waiting on a random draw to happen to land on something live.
    The blocklist is still enforced: a blocklisted `target_ip` is refused, the same as
    it would be excluded from random selection. ZMap's own discovery probe is skipped
    in this mode (the caller is asserting the target is worth grabbing directly,
    exactly how ZGrab2 is normally invoked standalone) but ZGrab2 and everything
    downstream of it - fingerprinting, dedup, Observation/Version recording - is
    identical to the random path via `_grab_and_record`.

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
                current_state=current_state, today=today, clock=clock,
                outcome=outcome, metadata=metadata,
            )
        metadata.ended_at = clock()
        metadata.status = "completed"
        return outcome

    logger.info(
        "scan %s: starting %d candidates, protocol=%s port=%d seed=%d",
        scan_id, candidate_count, protocol, port, seed,
    )

    for i in range(candidate_count):
        rate_limiter.wait()
        candidate_seed = derive_seed(seed, i)
        ip = probe_one(port, candidate_seed, blocklist_path, run_command=run_command)
        metadata.targets_attempted += 1
        if ip is None:
            logger.info(
                "scan %s [%d/%d] seed=%d: no response", scan_id, i + 1, candidate_count,
                candidate_seed,
            )
            continue
        logger.info(
            "scan %s [%d/%d] seed=%d: %s responded, grabbing", scan_id, i + 1, candidate_count,
            candidate_seed, ip,
        )

        rate_limiter.wait()
        _grab_and_record(
            scan_id=scan_id, protocol=protocol, ip=ip, port=port,
            zgrab2_module=zgrab2_module, blocklist_path=blocklist_path,
            run_command=run_command,
            current_state=current_state, today=today, clock=clock,
            outcome=outcome, metadata=metadata,
        )

    metadata.ended_at = clock()
    metadata.status = "completed"
    return outcome
