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
    """Write in ZMap's `--blocklist-file` format: one CIDR per line."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        for cidr in cidrs:
            f.write(f"{cidr}\n")
