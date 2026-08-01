"""Core record types shared across storage backends, the scanner, and the publisher.

These mirror the operational-data tables in the design doc (Exclusions, ScanSchedule,
ScanMetadata, CurrentState) plus the analytical rows that get batched to Opteryx.
"""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from enum import Enum
from typing import Any
from typing import Dict
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ExclusionSource(str, Enum):
    SELF_SERVE = "self-serve"
    JURISDICTION = "jurisdiction"
    MANUAL = "manual"


@dataclass(frozen=True)
class Exclusion:
    """One row of the Exclusions table: an opted-out IP or CIDR."""

    ip_or_cidr: str
    source: ExclusionSource
    requested_at: datetime = field(default_factory=utcnow)
    reason: Optional[str] = None
    requester_ip: Optional[str] = None


@dataclass(frozen=True)
class ScheduleEntry:
    """One row of the ScanSchedule table."""

    protocol: str
    port: int
    zgrab2_module: str
    enabled: bool = True
    cadence: str = "daily"
    rate_share: float = 1.0
    """Fraction (0-1] of the global rate budget this protocol may use when more than
    one protocol is enabled. MVP has http+https splitting the budget evenly."""


@dataclass
class ScanMetadataRecord:
    """One row of the ScanMetadata table, written once a scan run finishes."""

    scan_id: str
    protocol: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    targets_attempted: int = 0
    hosts_responsive: int = 0
    status: str = "running"
    seed: Optional[int] = None
    software_versions: Dict[str, str] = field(default_factory=dict)
    commit_id: Optional[str] = None
    rows_written: Optional[int] = None


@dataclass(frozen=True)
class CurrentStateRecord:
    """One row of the CurrentState dedup index: protocol#ip#port -> latest fingerprint."""

    protocol: str
    ip: str
    port: int
    fingerprint_id: str
    last_seen_date: str  # ISO date, not datetime - this is a daily dedup granularity

    @property
    def key(self) -> str:
        return f"{self.protocol}#{self.ip}#{self.port}"


@dataclass(frozen=True)
class Observation:
    """One row of the Observations analytical dataset."""

    scan_id: str
    observed_at: datetime
    ip: str
    port: int
    protocol: str
    response_status: str
    # None when a host answered ZMap's discovery probe but ZGrab2 couldn't complete a
    # grab (response_status="grab-failed") - there's no protocol payload to fingerprint,
    # but the fact that *something* is listening on the port is itself worth recording.
    fingerprint_id: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "observed_at": self.observed_at.isoformat(),
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "response_status": self.response_status,
            "fingerprint_id": self.fingerprint_id,
        }


@dataclass(frozen=True)
class VersionRecord:
    """One row of the Versions analytical dataset - an immutable, new fingerprint."""

    fingerprint_id: str
    protocol: str
    first_seen: datetime
    payload: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "protocol": self.protocol,
            "first_seen": self.first_seen.isoformat(),
            "payload": self.payload,
        }
