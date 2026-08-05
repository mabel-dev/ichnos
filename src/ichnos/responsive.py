"""The known-responsive host list, derived from published Observations.

Which addresses have answered recently is asked twice: discovery excludes them so its
candidates go to unknown space, and `refresh` uses them as its target list, oldest
checked first. A DynamoDB table (`CurrentState`) used to answer both, and this replaced
it entirely - everything either caller needs is already in the `observations` dataset,
which records every responsive host with its protocol and timestamp.

That swap changed three things:

The per-tick full-table scan went away. `_rebuild_blocklist` called
`current_state.list_all()` before every run - a DynamoDB Scan (a filtered one, so it
read the whole table and discarded two thirds), three times an hour against a table
that reached 124,357 items and was still growing by tens of thousands a day.

The list became bounded and self-healing. The table was permanent: a host that answered
once was excluded from discovery forever, so the blind spot only ever grew. A rolling
window means addresses that go dark re-enter the candidate pool, and discovery can
re-find a host that changed hands or came back.

And it introduces a lag - the list is only as fresh as the last refresh. That is
affordable at this address-space size: a newly-found host sits in the candidate pool
until the next rebuild, and the chance of a random draw landing on any specific address
again within a day is around 4 in 10,000. Against the hosts found per day that is on
the order of ten redundant probes out of more than a million.

The lag is only affordable while the list survives, though. A missing list is not a
small version of a stale one - it means discovery re-finds everything it already knows,
which is the failure this exists to prevent. Hence `refresh_protocol`'s contract: a
failed read leaves the previous file untouched and reports failure, and only a
genuinely empty result (which the feed distinguishes from failure by guarantee, see
odata.py) is allowed to write an empty list.
"""
from __future__ import annotations

import os
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Callable
from typing import List
from typing import Optional
from typing import Tuple

from .logging_setup import get_logger
from .odata import ODataError
from .odata import grouped_max

logger = get_logger(__name__)

DEFAULT_WINDOW_DAYS = 15
"""How far back an observation still counts as "responsive".

Sets two things at once: how long `refresh` keeps re-testing a host that has stopped
answering, and how quickly a dead address returns to discovery's candidate pool. With
refresh running nightly it is also, in effect, "give up after this many consecutive
non-responses". Chosen over the 30 first considered to keep the refresh target list
tighter - it is the cost side of the trade, re-grabbing hosts that may be long gone.
"""

OBSERVATIONS_DATASET = "observations"


def window_start(now: datetime, window_days: int = DEFAULT_WINDOW_DAYS) -> str:
    """The `observed_at ge ...` boundary, as an unquoted ISO-8601 literal.

    OData has no `now()` and no relative-date syntax, so the boundary is computed here
    and interpolated. Unquoted deliberately: quoting makes it a VARCHAR literal, and
    comparing that to a TIMESTAMP column is a 400, not a silent empty result.
    """
    return (now - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_responsive_hosts(
    protocol: str,
    *,
    workspace: str,
    collection: str,
    token: str,
    now: Optional[datetime] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    base_url: Optional[str] = None,
    get: Optional[Callable] = None,
) -> List[Tuple[str, str]]:
    """(ip, last_seen) for every host that answered `protocol` within the window,
    oldest-seen first.

    `response_status eq 'success'` and not merely "we have a row": observations are also
    written for `closed` (an RST - the host is up but the port is refused) and
    `grab-failed`. Neither belongs in this list. A closed port is exactly the kind of
    address discovery should keep sampling, and refresh has nothing to re-grab there.

    The `last_seen` half is what lets CurrentState go. Refresh works oldest-checked
    first, and that ordering used to come from a CurrentState column this code kept
    up to date. It comes from the observations themselves now: refresh writes an
    Observation for every host it re-checks, publish commits it within the hour, and
    the next derivation sees the newer max(observed_at) and sorts that host to the
    back. The cursor advances through the data pipeline rather than through a table
    maintained on the side.
    """
    now = now or datetime.now(timezone.utc)
    where = (
        f"protocol eq '{protocol}' and response_status eq 'success' "
        f"and observed_at ge {window_start(now, window_days)}"
    )
    kwargs = {"where": where, "token": token, "get": get}
    if base_url:
        kwargs["base_url"] = base_url
    rows = grouped_max(
        f"{workspace}/{collection}/{OBSERVATIONS_DATASET}",
        "ip", "observed_at", "last_seen", **kwargs
    )
    return sorted(
        ((r["ip"], r.get("last_seen") or "") for r in rows), key=lambda pair: pair[1]
    )


def write_responsive_file(path: str, hosts: List[Tuple[str, str]]) -> None:
    """`<ip> <last_seen>` per line, in the order given - which fetch_responsive_hosts
    leaves oldest-first, so refresh can stream the file and stop when its budget runs
    out without sorting anything itself.

    Written to a temp file and atomically renamed, for the same reason
    write_blocklist_file is (blocklist.py): a reader can otherwise catch a half-written
    file, and this one is read at the start of every scan."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        for ip, last_seen in hosts:
            f.write(f"{ip} {last_seen}\n")
    os.replace(tmp_path, path)


def read_responsive_hosts(path: str) -> List[Tuple[str, str]]:
    """Read back `<ip> <last_seen>` pairs, preserving file order (oldest-first).

    A missing file is an empty list, not an error - a freshly-built instance has no
    copy until the boot-time derivation runs, and that must not stop it scanning.
    Lines carrying only an address are tolerated so an older file still parses; they
    sort first, which for refresh means "check these soonest" - the safe reading of
    "we do not know when this was last seen"."""
    if not os.path.exists(path):
        return []
    hosts = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if parts:
                hosts.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return hosts


def read_responsive_file(path: str) -> List[str]:
    """Just the addresses, for the blocklist layer - which does not care when a host
    was last seen, only that discovery should skip it."""
    return [ip for ip, _ in read_responsive_hosts(path)]


def refresh_protocol(
    protocol: str,
    path: str,
    *,
    workspace: str,
    collection: str,
    token: str,
    now: Optional[datetime] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    base_url: Optional[str] = None,
    get: Optional[Callable] = None,
) -> bool:
    """Refresh one protocol's list on disk. True if it was rewritten, False if the read
    failed and the previous copy was left in place.

    Never truncates on failure. "The query failed" and "nobody has responded" have to
    produce different behaviour, or a transient outage silently wipes the exclusion
    list and discovery spends the next day re-finding everything it already knew.
    """
    try:
        hosts = fetch_responsive_hosts(
            protocol,
            workspace=workspace,
            collection=collection,
            token=token,
            now=now,
            window_days=window_days,
            base_url=base_url,
            get=get,
        )
    except ODataError as exc:
        logger.error(
            "responsive-refresh %s: read failed, keeping the existing list (%d entries): %s",
            protocol, len(read_responsive_hosts(path)), exc,
        )
        return False

    write_responsive_file(path, hosts)
    logger.info(
        "responsive-refresh %s: %d responsive hosts -> %s (oldest %s)",
        protocol, len(hosts), path, hosts[0][1] if hosts else "n/a",
    )
    return True
