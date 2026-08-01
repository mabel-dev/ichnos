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
    *,
    run_command: CommandRunner = _default_run_command,
) -> Optional[dict]:
    """One ZGrab2 handshake against a single target. Returns the parsed `data.<module>`
    object, or None if ZGrab2 produced no parseable result."""
    output = run_command(["zgrab2", module, "--port", str(port)], f"{ip}\n")
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
) -> ScanRunOutcome:
    """Run one scan: up to `candidate_count` single-target probes, throttled by
    `rate_limiter`, fingerprinting and dedupe-checking every responsive host.

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
        module_result = grab_one(ip, port, zgrab2_module, run_command=run_command)
        if module_result is None:
            logger.info("scan %s: %s - zgrab2 produced no result", scan_id, ip)
            continue

        metadata.hosts_responsive += 1
        payload = normalize(protocol, module_result)
        fp_id = fingerprint_id(payload)

        current = current_state.get(protocol, ip, port)
        is_new = current is None or current.fingerprint_id != fp_id
        logger.info(
            "scan %s: %s fingerprint=%s (%s)", scan_id, ip, fp_id,
            "new" if is_new else "unchanged",
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

    metadata.ended_at = clock()
    metadata.status = "completed"
    return outcome
