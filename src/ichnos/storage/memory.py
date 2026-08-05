"""In-memory storage backend - local development and tests, not for production use."""
from __future__ import annotations

from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from ..models import Exclusion
from ..models import ScheduleEntry
from .base import ExclusionStore
from .base import ScheduleStore
from .base import Store
from .base import VersionIndexStore


class _MemoryExclusionStore(ExclusionStore):
    def __init__(self) -> None:
        self._rows: Dict[str, Exclusion] = {}

    def add(self, exclusion: Exclusion) -> None:
        self._rows[exclusion.ip_or_cidr] = exclusion

    def list_all(self) -> List[Exclusion]:
        return list(self._rows.values())


class _MemoryScheduleStore(ScheduleStore):
    def __init__(self) -> None:
        self._rows: Dict[str, ScheduleEntry] = {}

    def list_enabled(self) -> List[ScheduleEntry]:
        return [e for e in self._rows.values() if e.enabled]

    def get(self, protocol: str) -> Optional[ScheduleEntry]:
        return self._rows.get(protocol)

    def put(self, entry: ScheduleEntry) -> None:
        self._rows[entry.protocol] = entry


class _MemoryVersionIndexStore(VersionIndexStore):
    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def claim(self, fingerprint_id: str) -> bool:
        if fingerprint_id in self._seen:
            return False
        self._seen.add(fingerprint_id)
        return True


class InMemoryStore(Store):
    def __init__(self) -> None:
        self.exclusions = _MemoryExclusionStore()
        self.schedule = _MemoryScheduleStore()
        self.version_index = _MemoryVersionIndexStore()
