"""Weekly jurisdiction pre-exclusion refresh job (design doc §3.1.1).

Produces a flat CIDR list for the jurisdictions the project has decided to pre-exclude
as comprehensively as IP-level blocking allows: Japan, North Korea, South Korea, China,
Russia, and Iran. This is deliberately a *separate* artifact from the self-serve
`Exclusions` table (blocklist.py merges the two at scan time) - country allocations run
to thousands of CIDRs, which is cheap as a flat file and needlessly expensive as
individual DynamoDB items.

Two sources are supported:
    - "rir" (recommended, default): the country's Regional Internet Registry's own
      delegated-extended statistics file - authoritative, auditable, no third-party
      trust dependency. This matters because the exclusion exists for compliance
      reasons, not convenience.
    - "ipdeny": pre-aggregated third-party per-country zone files
      (ipdeny.com/ipblocks/data/countries/{cc}.zone). Faster to stand up, less
      auditable - an acceptable MVP fallback, not the long-term choice.

Known limitation, stated here rather than implied: country-coded IP allocation is a
best-effort proxy for jurisdiction, not a guarantee - cloud/CDN/VPN address space can
put a host's effective location outside its allocated country code. This reduces
exposure, it doesn't eliminate it.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Tuple

DEFAULT_COUNTRIES: Tuple[str, ...] = ("JP", "KP", "KR", "CN", "RU", "IR")

RIR_DELEGATED_STATS_URLS: Dict[str, str] = {
    "apnic": "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

# Which RIR registers each target country's allocations - avoids fetching all five
# multi-megabyte stats files when we already know where these six are registered.
# Extending to a new country: add its RIR here (see e.g. the RIR's own "which registry"
# lookup) - everything else in this module is generic.
COUNTRY_RIR_HINT: Dict[str, str] = {
    "JP": "apnic",
    "KP": "apnic",
    "KR": "apnic",
    "CN": "apnic",
    "RU": "ripencc",
    "IR": "ripencc",
}

IPDENY_URL_TEMPLATE = "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"

Fetcher = Callable[[str], str]


def _default_fetch(url: str) -> str:
    import requests

    response = requests.get(url, timeout=120)
    response.raise_for_status()
    return response.text


@dataclass(frozen=True)
class JurisdictionRefreshResult:
    cidrs: List[str]
    source: str
    countries: Tuple[str, ...]
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def count(self) -> int:
        return len(self.cidrs)


def _range_to_cidrs(start: str, count: int) -> List[str]:
    """Convert an RIR delegated-stats (start_ip, address_count) pair into the minimal
    equivalent set of CIDR blocks - counts are frequently not powers of two."""
    first = ipaddress.IPv4Address(start)
    last = ipaddress.IPv4Address(int(first) + count - 1)
    return [str(net) for net in ipaddress.summarize_address_range(first, last)]


def parse_delegated_stats(text: str, country_codes: Iterable[str]) -> List[str]:
    """Parse an RIR delegated-extended file, returning CIDRs for the given country
    codes only (case-sensitive, RIR files use uppercase ISO 3166-1 alpha-2)."""
    wanted = set(country_codes)
    cidrs: List[str] = []
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("2|"):
            continue
        fields = line.split("|")
        if len(fields) < 7:
            continue
        _registry, cc, record_type, start, value, *_rest = fields
        if cc not in wanted or record_type != "ipv4":
            continue
        try:
            cidrs.extend(_range_to_cidrs(start, int(value)))
        except (ValueError, ipaddress.AddressValueError):
            continue
    return cidrs


def _collapse(cidrs: Iterable[str]) -> List[str]:
    networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    return [str(n) for n in sorted(ipaddress.collapse_addresses(networks))]


def refresh_from_rir(
    countries: Iterable[str] = DEFAULT_COUNTRIES,
    *,
    fetch: Fetcher = _default_fetch,
    rir_hint: Dict[str, str] = COUNTRY_RIR_HINT,
) -> JurisdictionRefreshResult:
    countries = tuple(countries)
    rirs_needed = set()
    for cc in countries:
        if cc not in rir_hint:
            raise ValueError(
                f"no RIR hint for country {cc!r} - add one to COUNTRY_RIR_HINT "
                "(or extend rir_hint) rather than silently fetching all five registries"
            )
        rirs_needed.add(rir_hint[cc])

    all_cidrs: List[str] = []
    for rir in rirs_needed:
        text = fetch(RIR_DELEGATED_STATS_URLS[rir])
        wanted_here = [cc for cc in countries if rir_hint[cc] == rir]
        all_cidrs.extend(parse_delegated_stats(text, wanted_here))

    return JurisdictionRefreshResult(
        cidrs=_collapse(all_cidrs), source="rir", countries=countries
    )


def refresh_from_ipdeny(
    countries: Iterable[str] = DEFAULT_COUNTRIES,
    *,
    fetch: Fetcher = _default_fetch,
    url_template: str = IPDENY_URL_TEMPLATE,
) -> JurisdictionRefreshResult:
    countries = tuple(countries)
    all_cidrs: List[str] = []
    for cc in countries:
        text = fetch(url_template.format(cc=cc.lower()))
        all_cidrs.extend(line.strip() for line in text.splitlines() if line.strip())

    return JurisdictionRefreshResult(
        cidrs=_collapse(all_cidrs), source="ipdeny", countries=countries
    )


def refresh_jurisdiction_blocklist(
    countries: Iterable[str] = DEFAULT_COUNTRIES,
    *,
    source: str = "rir",
    fetch: Fetcher = _default_fetch,
) -> JurisdictionRefreshResult:
    if source == "rir":
        return refresh_from_rir(countries, fetch=fetch)
    if source == "ipdeny":
        return refresh_from_ipdeny(countries, fetch=fetch)
    raise ValueError(f"unknown jurisdiction blocklist source: {source!r}")
