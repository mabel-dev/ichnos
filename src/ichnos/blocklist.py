"""Build the ZMap blocklist file for a scan run (design doc §3.1.1, §4).

Three layers are merged, in this order, before every single scan run:
    1. Standard bogon/reserved/special-use IPv4 ranges (always excluded, static).
    2. The live `Exclusions` table (self-serve opt-outs) - so an opt-out takes effect
       on the very next scheduled scan.
    3. `jurisdiction-blocklist.conf` (JP/KP/KR/CN/RU/IR) - refreshed weekly by
       jurisdiction.py, read fresh here so a stale local copy is never used.
"""
from __future__ import annotations

import ipaddress
import os
import tempfile
from typing import Iterable
from typing import List
from typing import Union

IPNetwork = Union[ipaddress.IPv4Network]

# IANA special-purpose IPv4 address registry - never scanned regardless of any other
# configuration. Source: https://www.iana.org/assignments/iana-ipv4-special-registry/
DEFAULT_BOGONS: List[str] = [
    "0.0.0.0/8",  # "this host on this network"
    "10.0.0.0/8",  # private use
    "100.64.0.0/10",  # shared address space (CGNAT)
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link local
    "172.16.0.0/12",  # private use
    "192.0.0.0/24",  # IETF protocol assignments
    "192.0.2.0/24",  # documentation (TEST-NET-1)
    "192.88.99.0/24",  # 6to4 relay anycast
    "192.168.0.0/16",  # private use
    "198.18.0.0/15",  # benchmarking
    "198.51.100.0/24",  # documentation (TEST-NET-2)
    "203.0.113.0/24",  # documentation (TEST-NET-3)
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved for future use
    "255.255.255.255/32",  # limited broadcast
]


def _parse(entry: str) -> IPNetwork:
    """Accept either a bare IP (treated as /32) or a CIDR, reject anything else."""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        raise ValueError(f"not a valid blocklist entry: {entry!r}")
    if "/" not in entry:
        entry = f"{entry}/32"
    return ipaddress.ip_network(entry, strict=False)


def build_blocklist(
    *,
    exclusion_entries: Iterable[str] = (),
    jurisdiction_cidrs: Iterable[str] = (),
    bogons: Iterable[str] = DEFAULT_BOGONS,
) -> List[str]:
    """Merge all three layers, dedupe, and collapse into the smallest equivalent set
    of CIDRs (this matters once the jurisdiction list alone can be thousands of
    entries). Invalid entries are skipped rather than raised, since this runs against
    live user-submitted opt-out data - one bad entry shouldn't block an entire scan.
    """
    networks: List[IPNetwork] = []
    for entry in (*bogons, *exclusion_entries, *jurisdiction_cidrs):
        try:
            networks.append(_parse(entry))
        except ValueError:
            continue
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(net) for net in sorted(collapsed)]


def write_blocklist_file(path: str, cidrs: Iterable[str]) -> None:
    """Write in ZMap's `--blocklist-file` format: one CIDR per line.

    Writes to a temp file in the same directory and atomically renames it into place
    (os.replace) rather than truncating the destination directly. Real, previously-
    undetected production bug: http/https/ssh each independently call this against
    the *same* shared blocklist path within the same cron tick (all three fire within
    the same second) - a concurrently-running ZMap process reading this file mid-write
    would see a truncated CIDR, confirmed in production: a line cut off as literally
    "103." (missing the rest of the address), which made ZMap fatal-error and refuse
    to start at all ("unable to parse blacklist file"), reported as a failed scan
    (see scanner.py's exit-code check) rather than silently corrupting results.
    os.replace is atomic on POSIX, so any concurrent reader always sees either the
    complete old file or the complete new one, never an in-between state.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".blocklist-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for cidr in cidrs:
                f.write(f"{cidr}\n")
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def read_blocklist_file(path: str) -> List[str]:
    """The inverse of `write_blocklist_file` - used by anything that needs to check a
    single address against the already-built blocklist (e.g. a deliberately-targeted
    scan, see scanner.py's `target_ip`) rather than rebuilding it from scratch."""
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def is_blocked(ip: str, cidrs: Iterable[str]) -> bool:
    """Whether `ip` falls inside any of `cidrs`. Restrictions are enforced the same
    way regardless of how a target was chosen - random draw or deliberately
    specified - this is the one place that check happens."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a valid address at all - treat as blocked, not as "allowed"
    return any(address in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)
